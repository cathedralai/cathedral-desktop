// boxd runs inside a sealed TEE box.
//
// It keeps the AB#361 link as it was: a fresh ECDSA P-256 TLS key at boot, its SPKI hash in
// REPORT_DATA through configfs-tsm, and the "JOB" / "REPORT" line protocol over TLS 1.3 on 8443.
//
// It adds the sealed stream on 8444 (tee/SEALED-STREAM.md): a static X25519 key, also fresh at
// boot, bound into REPORT_DATA; a Noise_NK_25519_AESGCM_SHA256 handshake whose prologue binds the
// report; then AES-GCM frames piped to a target inside the box (vnc 127.0.0.1:5901, cdp
// 127.0.0.1:9222, job). Any relay in between carries ciphertext only.
//
// Standard library only, so it builds on an offline host: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	protocolName   = "Noise_NK_25519_AESGCM_SHA256"
	prologueLabel  = "sealed-stream/v1"
	maxFrame       = 1 << 20 // wire limit for any frame
	maxData        = 64 << 10
	rekeyEvery     = 1 << 20 // frames per key
	tsmDir         = "/sys/kernel/config/tsm/report/boxd"
	targetVNC      = "127.0.0.1:5901"
	targetCDP      = "127.0.0.1:9222"
	consoleDevice  = "/dev/ttyS0"
	reportDataSize = 64
)

var (
	flagDev      = flag.Bool("dev", false, "development box: no TSM report, no console, listen on loopback")
	flagNoTicket = flag.Bool("noticket", false, "accept an empty ticket (private spike only)")
	flagTLSAddr  = flag.String("tls", ":8443", "AB#361 TLS line protocol address")
	flagSSAddr   = flag.String("stream", ":8444", "sealed stream address")
	flagCerts    = flag.String("certs", "/etc/boxd/certs", "directory with vcek.der, ask.der, ark.der (optional)")
	flagTicketPK = flag.String("ticket-key", "/etc/boxd/ticket.pub", "Cathedral ticket public key, raw Ed25519 (optional)")
	flagVNC      = flag.String("target-vnc", targetVNC, "address behind target vnc")
	flagCDP      = flag.String("target-cdp", targetCDP, "address behind target cdp")
)

func main() {
	flag.Parse()
	if *flagDev {
		if *flagTLSAddr == ":8443" {
			*flagTLSAddr = "127.0.0.1:8443"
		}
		if *flagSSAddr == ":8444" {
			*flagSSAddr = "127.0.0.1:8444"
		}
	}

	// AB#361 TLS key, unchanged.
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sealed-box"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		fail(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		fail(err)
	}
	spkiSum := sha256.Sum256(spki)
	console("KEY " + hex.EncodeToString(spkiSum[:]))
	certSum := sha256.Sum256(der)
	console("CERT " + hex.EncodeToString(certSum[:]))

	// Sealed stream static key.
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fail(err)
	}
	staticPub := static.PublicKey().Bytes()
	staticSum := sha256.Sum256(staticPub)
	console("STREAMKEY " + hex.EncodeToString(staticSum[:]))

	// REPORT_DATA = sha256(canonical(binding)) || 32 zero bytes, the layout sealed secrets and the
	// miner hotels use (cathedral-sandbox docs/SEALED_SECRETS.md), so one verifier serves every lane.
	// The binding names each key: the AB#361 TLS key as tls_spki_sha256, the stream key under
	// sealed_stream. Canonical form: sorted keys, compact separators, raw UTF-8.
	binding := canonicalJSON(map[string]any{
		"tls_spki_sha256": hex.EncodeToString(spkiSum[:]),
		"sealed_stream": map[string]any{
			"schema":            "sealed-stream/v1",
			"x25519_public_b64": base64.StdEncoding.EncodeToString(staticPub),
		},
	})
	bindSum := sha256.Sum256(binding)
	var reportData [reportDataSize]byte
	copy(reportData[:32], bindSum[:])
	console("BINDING " + hex.EncodeToString(bindSum[:]))
	box := &boxState{static: static, staticPub: staticPub, binding: binding, certs: loadCerts(*flagCerts), ticketPub: loadTicketKey(*flagTicketPK), seen: &seenTickets{used: map[[32]byte]int64{}}}
	if !*flagDev {
		box.report = attest(reportData[:])
	} else {
		console("DEV no attestation")
	}
	if *flagNoTicket {
		console("NOTICKET")
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: tlsKey}}}
	tl, err := tls.Listen("tcp", *flagTLSAddr, cfg)
	if err != nil {
		fail(err)
	}
	sl, err := net.Listen("tcp", *flagSSAddr)
	if err != nil {
		fail(err)
	}
	console("LISTEN " + *flagTLSAddr + " " + *flagSSAddr)
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				continue
			}
			go serveTLS(c, box)
		}
	}()
	for {
		c, err := sl.Accept()
		if err != nil {
			continue
		}
		go serveStream(c, box)
	}
}

type boxState struct {
	static    *ecdh.PrivateKey
	staticPub []byte
	report    []byte
	certs     map[string][]byte
	ticketPub []byte
	binding   []byte
	seen      *seenTickets
}

// ---- AB#361 line protocol (unchanged behaviour)

func serveTLS(c net.Conn, box *boxState) {
	defer c.Close()
	r := bufio.NewScanner(c)
	for r.Scan() {
		f := strings.Fields(r.Text())
		if len(f) == 1 && f[0] == "REPORT" {
			if box.report == nil {
				fmt.Fprintln(c, "NOREPORT")
			} else {
				fmt.Fprintf(c, "REPORT %s\n", hex.EncodeToString(box.report))
			}
		}
		if len(f) == 2 && f[0] == "JOB" {
			fmt.Fprintf(c, "DONE %s %d\n", f[1], 6*7)
		}
	}
}

// ---- sealed stream

type hello struct {
	V int `json:"v"`
}

type attestMsg struct {
	V       int               `json:"v"`
	Static  string            `json:"static"`
	Binding string            `json:"binding"`
	Report  string            `json:"report"`
	Certs   map[string]string `json:"certs,omitempty"`
	Dev     bool              `json:"dev,omitempty"`
}

type openMsg struct {
	Target string `json:"target"`
	Ticket string `json:"ticket"`
}

func serveStream(c net.Conn, box *boxState) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	// 1. HELLO
	raw, err := readFrame(c)
	if err != nil {
		return
	}
	var h hello
	if json.Unmarshal(raw, &h) != nil || h.V != 1 {
		writeFrame(c, []byte(`{"error":"bad hello"}`))
		return
	}
	// 2. ATTEST
	att := attestMsg{V: 1, Static: b64(box.staticPub), Binding: string(box.binding), Report: b64(box.report), Dev: box.report == nil}
	if len(box.certs) > 0 {
		att.Certs = map[string]string{}
		for k, v := range box.certs {
			att.Certs[k] = b64(v)
		}
	}
	aj, _ := json.Marshal(att)
	if writeFrame(c, aj) != nil {
		return
	}
	// 3. Noise NK, responder side. Prologue binds the protocol label and the report.
	repSum := sha256.Sum256(box.report)
	prologue := append([]byte(prologueLabel), repSum[:]...)
	hs := newHandshake(prologue, box.static)
	msg1, err := readFrame(c)
	if err != nil {
		return
	}
	payload1, err := hs.readMessage1(msg1)
	if err != nil {
		writeFrame(c, []byte(`{"error":"handshake"}`))
		return
	}
	var open openMsg
	if json.Unmarshal(payload1, &open) != nil {
		writeFrame(c, []byte(`{"error":"bad open"}`))
		return
	}
	target, err := resolveTarget(open.Target)
	if err != nil {
		writeFrame(c, []byte(`{"error":"unknown target"}`))
		return
	}
	if !ticketOK(box, open) {
		// Still complete the handshake so the client gets an authenticated refusal.
		msg2, _ := hs.writeMessage2([]byte(`{"ok":false,"error":"ticket refused"}`))
		writeFrame(c, msg2)
		return
	}
	var up net.Conn
	if target != "job" {
		up, err = net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			msg2, _ := hs.writeMessage2([]byte(`{"ok":false,"error":"target not listening"}`))
			writeFrame(c, msg2)
			return
		}
		defer up.Close()
	}
	msg2, err := hs.writeMessage2([]byte(`{"ok":true}`))
	if err != nil {
		return
	}
	if writeFrame(c, msg2) != nil {
		return
	}
	send, recv := hs.split()
	c.SetDeadline(time.Time{})
	console("STREAM " + open.Target)
	if target == "job" {
		pipeJob(c, send, recv)
		return
	}
	pipe(c, up, send, recv)
}

func resolveTarget(t string) (string, error) {
	switch t {
	case "vnc":
		return *flagVNC, nil
	case "cdp":
		return *flagCDP, nil
	case "job":
		return "job", nil
	}
	return "", errors.New("unknown target")
}

// ticketOK checks the Cathedral ticket: Ed25519 over {"box","target","exp","nonce"} with the pinned
// key, then marks it used. NK gives the client's first message no freshness from the box, so a
// replayed message 1 would reopen the target: single-use tickets with a short expiry close that.
// Until the ticket mint exists, -noticket accepts an empty ticket and says so on the console.
func ticketOK(box *boxState, open openMsg) bool {
	if open.Ticket == "" {
		return *flagNoTicket
	}
	if box.ticketPub == nil {
		return false
	}
	exp, ok := verifyTicket(box.ticketPub, open.Ticket, open.Target, box.staticPub)
	if !ok {
		return false
	}
	return box.seen.use(open.Ticket, exp)
}

// seenTickets remembers used tickets until they expire.
type seenTickets struct {
	mu   sync.Mutex
	used map[[32]byte]int64
}

func (s *seenTickets) use(ticket string, exp int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, e := range s.used {
		if e < now {
			delete(s.used, k)
		}
	}
	key := sha256.Sum256([]byte(ticket))
	if _, dup := s.used[key]; dup {
		console("TICKET replay refused")
		return false
	}
	s.used[key] = exp
	return true
}

// ---- framing

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, errors.New("frame too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeFrame(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// ---- data phase: each direction its own CipherState, strict counters, rekey every rekeyEvery frames

func pipe(c net.Conn, up net.Conn, send, recv *cipherState) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { c.Close(); up.Close() }) }
	go func() {
		defer closeBoth()
		buf := make([]byte, maxData)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				ct, err2 := send.encrypt(buf[:n])
				if err2 != nil || writeFrame(c, ct) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	defer closeBoth()
	for {
		ct, err := readFrame(c)
		if err != nil {
			return
		}
		pt, err := recv.decrypt(ct)
		if err != nil {
			console("STREAM auth failure, closing")
			return
		}
		if _, err := up.Write(pt); err != nil {
			return
		}
	}
}

// pipeJob answers "JOB <id>" lines inside the stream, for interop tests without a desktop.
func pipeJob(c net.Conn, send, recv *cipherState) {
	for {
		ct, err := readFrame(c)
		if err != nil {
			return
		}
		pt, err := recv.decrypt(ct)
		if err != nil {
			return
		}
		f := strings.Fields(string(pt))
		var reply string
		if len(f) == 2 && f[0] == "JOB" {
			reply = fmt.Sprintf("DONE %s %d\n", f[1], 6*7)
		} else {
			reply = "ERR\n"
		}
		rct, err := send.encrypt([]byte(reply))
		if err != nil || writeFrame(c, rct) != nil {
			return
		}
	}
}

// ---- Noise_NK_25519_AESGCM_SHA256 (responder), per the Noise spec revision 34

type cipherState struct {
	k      []byte
	n      uint64
	aead   cipher.AEAD
	frames uint64
}

func newCipherState(k []byte) *cipherState {
	cs := &cipherState{}
	cs.initKey(k)
	return cs
}

func (cs *cipherState) initKey(k []byte) {
	cs.k = append([]byte(nil), k...)
	block, err := aes.NewCipher(cs.k)
	if err != nil {
		panic(err)
	}
	cs.aead, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	cs.n = 0
}

func (cs *cipherState) nonce() []byte {
	var nb [12]byte
	binary.BigEndian.PutUint64(nb[4:], cs.n)
	return nb[:]
}

func (cs *cipherState) encryptWithAd(ad, pt []byte) ([]byte, error) {
	if cs.aead == nil {
		return pt, nil
	}
	if cs.n == ^uint64(0) {
		return nil, errors.New("nonce exhausted")
	}
	ct := cs.aead.Seal(nil, cs.nonce(), pt, ad)
	cs.n++
	return ct, nil
}

func (cs *cipherState) decryptWithAd(ad, ct []byte) ([]byte, error) {
	if cs.aead == nil {
		return ct, nil
	}
	if cs.n == ^uint64(0) {
		return nil, errors.New("nonce exhausted")
	}
	pt, err := cs.aead.Open(nil, cs.nonce(), ct, ad)
	if err != nil {
		return nil, err
	}
	cs.n++
	return pt, nil
}

func (cs *cipherState) rekey() {
	// REKEY(k) = ENCRYPT(k, maxnonce, zerolen, zeros[32])[:32]
	var nb [12]byte
	binary.BigEndian.PutUint64(nb[4:], ^uint64(0))
	nk := cs.aead.Seal(nil, nb[:], make([]byte, 32), nil)[:32]
	cs.initKey(nk)
}

func (cs *cipherState) encrypt(pt []byte) ([]byte, error) {
	if len(pt) > maxData {
		return nil, errors.New("frame over maxData")
	}
	ct, err := cs.encryptWithAd(nil, pt)
	if err != nil {
		return nil, err
	}
	cs.frames++
	if cs.frames%rekeyEvery == 0 {
		cs.rekey()
	}
	return ct, nil
}

func (cs *cipherState) decrypt(ct []byte) ([]byte, error) {
	pt, err := cs.decryptWithAd(nil, ct)
	if err != nil {
		return nil, err
	}
	cs.frames++
	if cs.frames%rekeyEvery == 0 {
		cs.rekey()
	}
	return pt, nil
}

type handshake struct {
	ck   []byte
	h    []byte
	cs   *cipherState
	s    *ecdh.PrivateKey
	e    *ecdh.PrivateKey
	re   *ecdh.PublicKey
	done bool
}

func newHandshake(prologue []byte, s *ecdh.PrivateKey) *handshake {
	hs := &handshake{s: s, cs: &cipherState{}}
	name := []byte(protocolName)
	if len(name) <= 32 {
		hs.h = make([]byte, 32)
		copy(hs.h, name)
	} else {
		sum := sha256.Sum256(name)
		hs.h = sum[:]
	}
	hs.ck = append([]byte(nil), hs.h...)
	hs.mixHash(prologue)
	hs.mixHash(s.PublicKey().Bytes()) // NK pre-message: <- s
	return hs
}

func (hs *handshake) mixHash(data []byte) {
	sum := sha256.Sum256(append(append([]byte(nil), hs.h...), data...))
	hs.h = sum[:]
}

func (hs *handshake) mixKey(ikm []byte) {
	ck, k := hkdf2(hs.ck, ikm)
	hs.ck = ck
	hs.cs.initKey(k)
}

// readMessage1 handles "-> e, es" and returns the decrypted payload (target and ticket).
func (hs *handshake) readMessage1(msg []byte) ([]byte, error) {
	if len(msg) < 32 {
		return nil, errors.New("short message 1")
	}
	re, err := ecdh.X25519().NewPublicKey(msg[:32])
	if err != nil {
		return nil, err
	}
	hs.re = re
	hs.mixHash(msg[:32])
	es, err := hs.s.ECDH(re)
	if err != nil {
		return nil, err
	}
	hs.mixKey(es)
	pt, err := hs.cs.decryptWithAd(hs.h, msg[32:])
	if err != nil {
		return nil, err
	}
	hs.mixHash(msg[32:])
	return pt, nil
}

// writeMessage2 handles "<- e, ee" with a payload; after it the transport keys are ready.
func (hs *handshake) writeMessage2(payload []byte) ([]byte, error) {
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hs.e = e
	eb := e.PublicKey().Bytes()
	hs.mixHash(eb)
	ee, err := e.ECDH(hs.re)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ee)
	ct, err := hs.cs.encryptWithAd(hs.h, payload)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ct)
	hs.done = true
	return append(eb, ct...), nil
}

// split returns (responder send, responder receive): initiator's send key is the first output.
func (hs *handshake) split() (*cipherState, *cipherState) {
	k1, k2 := hkdf2(hs.ck, nil)
	return newCipherState(k2), newCipherState(k1)
}

func hkdf2(ck, ikm []byte) ([]byte, []byte) {
	temp := hmacSHA256(ck, ikm)
	out1 := hmacSHA256(temp, []byte{0x01})
	out2 := hmacSHA256(temp, append(append([]byte(nil), out1...), 0x02))
	return out1, out2
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ---- ticket (shape only until the mint exists)

// verifyTicket checks shape, box, target, expiry (at most 10 minutes ahead) and signature; returns exp.
//
// The ticket names the box by its stream key, not by a room id. The key is this
// box's and only this box's: it is made at boot, it is what REPORT_DATA commits
// to, and the box hands it to the client in ATTEST before any ticket is asked
// for, so a minter can always name it. A room id would have to reach the box on
// its measured command line, which would give every box a different measurement,
// and a ticket that names nothing opens every box that pins the same mint key.
func verifyTicket(pub []byte, ticket, target string, staticPub []byte) (int64, bool) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return 0, false
	}
	body, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(sig) != 64 || len(pub) != 32 {
		return 0, false
	}
	var t struct {
		Box    string `json:"box"`
		Target string `json:"target"`
		Exp    int64  `json:"exp"`
		Nonce  string `json:"nonce"`
	}
	now := time.Now().Unix()
	if json.Unmarshal(body, &t) != nil || t.Target != target || now > t.Exp || t.Exp > now+600 {
		return 0, false
	}
	if t.Box != base64.StdEncoding.EncodeToString(staticPub) {
		console("TICKET for another box refused")
		return 0, false
	}
	// Two tickets minted in the same second for one target would otherwise be
	// byte-identical, and the second would be refused as its own replay: the
	// nonce is what makes parallel connections (CDP opens several) possible.
	if t.Nonce == "" {
		console("TICKET without a nonce refused")
		return 0, false
	}
	if !ed25519Verify(pub, body, sig) {
		return 0, false
	}
	return t.Exp, true
}

// ---- attestation and files

// attest gets an SEV-SNP report through configfs-tsm for the given 64-byte REPORT_DATA.
func attest(reportData []byte) []byte {
	if err := os.Mkdir(tsmDir, 0o700); err != nil && !os.IsExist(err) {
		console("ATTEST_ERROR mkdir " + err.Error())
		return nil
	}
	if err := os.WriteFile(tsmDir+"/inblob", reportData, 0o600); err != nil {
		console("ATTEST_ERROR inblob " + err.Error())
		return nil
	}
	out, err := os.ReadFile(tsmDir + "/outblob")
	if err != nil {
		console("ATTEST_ERROR outblob " + err.Error())
		return nil
	}
	prov, _ := os.ReadFile(tsmDir + "/provider")
	console(fmt.Sprintf("ATTEST ok bytes=%d provider=%s", len(out), strings.TrimSpace(string(prov))))
	return out
}

func loadCerts(dir string) map[string][]byte {
	out := map[string][]byte{}
	for _, n := range []string{"vcek", "ask", "ark"} {
		if b, err := os.ReadFile(dir + "/" + n + ".der"); err == nil {
			out[n] = b
		}
	}
	return out
}

func loadTicketKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// canonicalJSON matches Python's json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False):
// encoding/json sorts map keys and is compact; HTML escaping is turned off to keep <, > and & raw.
func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fail(err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func console(s string) {
	if *flagDev {
		fmt.Fprintln(os.Stderr, s)
		return
	}
	if f, err := os.OpenFile(consoleDevice, os.O_WRONLY, 0); err == nil {
		fmt.Fprintln(f, s)
		f.Close()
	}
}

func fail(err error) {
	console("BOXD_ERROR " + err.Error())
	os.Exit(1)
}
