package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// AB#353 WP3: boxd customer mode. The shared vector file is read by the JS and Python tests too.

type vectorFile struct {
	DomainHex string `json:"domain_hex"`
	Customer  struct {
		PubHex      string `json:"public_key_hex"`
		PubB64u     string `json:"public_key_b64u"`
		PreimageHex string `json:"preimage_hex"`
		HostDataHex string `json:"host_data_hex"`
	} `json:"customer"`
	Other struct {
		PubHex      string `json:"public_key_hex"`
		HostDataHex string `json:"host_data_hex"`
	} `json:"other_customer"`
	NoZero struct {
		HostDataHex string `json:"host_data_hex"`
	} `json:"without_trailing_zero"`
	Unlabelled struct {
		HostDataHex string `json:"host_data_hex"`
	} `json:"unlabelled_sha256_of_key"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../testdata/customer_host_data_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorRebuiltFromKey(t *testing.T) {
	v := loadVector(t)
	pub := unhex(t, v.Customer.PubHex)
	if got := hex.EncodeToString(customerHostData(pub)); got != v.Customer.HostDataHex {
		t.Fatalf("HOST_DATA from the key = %s, vector says %s", got, v.Customer.HostDataHex)
	}
	pre := unhex(t, v.Customer.PreimageHex)
	if !bytes.Equal(pre, append(unhex(t, v.DomainHex), pub...)) || !strings.HasSuffix(v.DomainHex, "00") {
		t.Fatal("vector preimage is not domain, zero byte, key")
	}
	sum := sha256.Sum256(pre)
	if hex.EncodeToString(sum[:]) != v.Customer.HostDataHex {
		t.Fatal("vector value is not sha256 of its stored preimage")
	}
	if got := hex.EncodeToString(customerHostData(unhex(t, v.Other.PubHex))); got != v.Other.HostDataHex {
		t.Fatalf("other key: %s want %s", got, v.Other.HostDataHex)
	}
	if v.NoZero.HostDataHex == v.Customer.HostDataHex || hex.EncodeToString(customerHostData(pub)) == v.NoZero.HostDataHex {
		t.Fatal("the domain without its trailing zero byte must give a different value")
	}
	bare := sha256.Sum256(pub)
	if hex.EncodeToString(bare[:]) != v.Unlabelled.HostDataHex || v.Unlabelled.HostDataHex == v.Customer.HostDataHex {
		t.Fatal("unlabelled vector is wrong")
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(v.Customer.PubB64u); err != nil || !bytes.Equal(raw, pub) {
		t.Fatal("stored b64url key does not decode to the stored key")
	}
}

func TestCheckCustomerHostData(t *testing.T) {
	v := loadVector(t)
	pub := unhex(t, v.Customer.PubHex)
	good := unhex(t, v.Customer.HostDataHex)
	if err := checkCustomerHostData(good, pub); err != nil {
		t.Fatalf("the right value was refused: %v", err)
	}
	refused := map[string][]byte{
		"different customer key": unhex(t, v.Other.HostDataHex),
		"all zero":               make([]byte, 32),
		"sha256(key) unlabelled": unhex(t, v.Unlabelled.HostDataHex),
		"no trailing zero byte":  unhex(t, v.NoZero.HostDataHex),
		"31 bytes":               good[:31],
		"33 bytes":               append(append([]byte{}, good...), 0),
		"empty":                  nil,
	}
	for name, hd := range refused {
		if err := checkCustomerHostData(hd, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkCustomerHostData(make([]byte, 32), pub); err == nil || !strings.Contains(err.Error(), "zero") {
		t.Errorf("all-zero must be refused by name, got %v", err)
	}
	for i := 0; i < 32; i++ {
		for _, bit := range []byte{0x01, 0x80} {
			h := append([]byte{}, good...)
			h[i] ^= bit
			if checkCustomerHostData(h, pub) == nil {
				t.Errorf("byte %d bit %#x changed: accepted", i, bit)
			}
		}
	}
	if err := checkCustomerHostData(good, pub[:31]); err == nil {
		t.Error("a 31-byte customer key was accepted")
	}
}

// customerRig is a box launched for one customer key, with a Cathedral ticket key pinned as well (which customer mode must ignore).
type customerRig struct {
	*ticketRig
	custPub  ed25519.PublicKey
	custPriv ed25519.PrivateKey
	field    string
}

func newCustomerRig(t *testing.T) *customerRig {
	t.Helper()
	r := newRig(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.box.customer = true
	r.box.hostData = customerHostData(pub)
	return &customerRig{ticketRig: r, custPub: pub, custPriv: priv, field: base64.RawURLEncoding.EncodeToString(pub)}
}

func (c *customerRig) signWith(priv ed25519.PrivateKey, b ticketBody) string {
	raw, _ := json.Marshal(b)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))
}

func (c *customerRig) admit(ticket, field string) error {
	return admit(c.box, openMsg{Target: "vnc", Ticket: ticket, Customer: field})
}

func TestCustomerValidKeyOpens(t *testing.T) {
	c := newCustomerRig(t)
	if err := c.admit(c.signWith(c.custPriv, c.body(nil)), c.field); err != nil {
		t.Fatalf("a ticket signed by the customer key, with its key in the open message, was refused: %v", err)
	}
}

func TestCustomerRefusals(t *testing.T) {
	c := newCustomerRig(t)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherField := base64.RawURLEncoding.EncodeToString(otherPub)
	cases := []struct{ name, ticket, field string }{
		{"customer key whose hash is not this box's HOST_DATA", c.signWith(otherPriv, c.body(nil)), otherField},
		{"Cathedral key signs the ticket, right customer field", c.sign(c.body(nil)), c.field},
		{"empty ticket, right customer field", "", c.field},
		{"ticket signed by another key, matching customer field", c.signWith(otherPriv, c.body(nil)), c.field},
		{"ticket for another box", c.signWith(c.custPriv, c.body(func(b *ticketBody) { b.Box = base64.StdEncoding.EncodeToString(randBytes(32)) })), c.field},
		{"ticket for another target", c.signWith(c.custPriv, c.body(func(b *ticketBody) { b.Target = "cdp" })), c.field},
		{"customer field is not base64url", c.signWith(c.custPriv, c.body(nil)), "!!!"},
		{"customer field is 31 bytes", c.signWith(c.custPriv, c.body(nil)), base64.RawURLEncoding.EncodeToString(c.custPub[:31])},
		{"customer field is 33 bytes", c.signWith(c.custPriv, c.body(nil)), base64.RawURLEncoding.EncodeToString(append(append([]byte{}, c.custPub...), 0))},
		{"customer field is padded", c.signWith(c.custPriv, c.body(nil)), base64.URLEncoding.EncodeToString(c.custPub)},
	}
	for _, tc := range cases {
		if err := c.admit(tc.ticket, tc.field); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if n := len(c.box.seen.used); n != 0 {
		t.Errorf("refused tickets were remembered: %d", n)
	}
}

func TestCustomerMissingFieldNamesCustomerMode(t *testing.T) {
	c := newCustomerRig(t)
	err := c.admit(c.signWith(c.custPriv, c.body(nil)), "")
	if err == nil || !strings.Contains(err.Error(), "customer mode") {
		t.Fatalf("a missing customer field must be refused with a message naming customer mode, got %v", err)
	}
}

func TestCustomerZeroHostDataRefusesEverything(t *testing.T) {
	c := newCustomerRig(t)
	c.box.hostData = make([]byte, 32)
	if err := c.admit(c.signWith(c.custPriv, c.body(nil)), c.field); err == nil {
		t.Fatal("a box whose HOST_DATA is zero opened a stream")
	}
	c.box.hostData = nil
	if err := c.admit(c.signWith(c.custPriv, c.body(nil)), c.field); err == nil {
		t.Fatal("a box with no HOST_DATA opened a stream")
	}
}

func TestCustomerReplayRefused(t *testing.T) {
	c := newCustomerRig(t)
	ticket := c.signWith(c.custPriv, c.body(nil))
	if err := c.admit(ticket, c.field); err != nil {
		t.Fatal(err)
	}
	if err := c.admit(ticket, c.field); err == nil {
		t.Fatal("the same ticket opened a second stream")
	}
}

func TestCustomerExpiryRulesStillApply(t *testing.T) {
	c := newCustomerRig(t)
	now := time.Now().Unix()
	for name, mut := range map[string]func(*ticketBody){
		"expired":    func(b *ticketBody) { b.Exp = now - 5 },
		"over 600 s": func(b *ticketBody) { b.Exp = now + 3600 },
		"no nonce":   func(b *ticketBody) { b.Nonce = "" },
	} {
		if err := c.admit(c.signWith(c.custPriv, c.body(mut)), c.field); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNonCustomerBoxIsUnchanged(t *testing.T) {
	r := newRig(t)
	if err := admit(r.box, openMsg{Target: "vnc", Ticket: r.sign(r.body(nil))}); err != nil {
		t.Fatalf("a Cathedral ticket on a box without customer mode was refused: %v", err)
	}
	if err := admit(r.box, openMsg{Target: "vnc", Ticket: ""}); err == nil {
		t.Fatal("an empty ticket was accepted without -noticket")
	}
	// A customer field means nothing to a box that is not in customer mode: the Cathedral rules decide.
	r2 := newRig(t)
	if err := admit(r2.box, openMsg{Target: "vnc", Ticket: r2.sign(r2.body(nil)), Customer: "AAAA"}); err != nil {
		t.Fatalf("a stray customer field changed the outcome off customer mode: %v", err)
	}
}

func setFlags(t *testing.T, dev, noticket, customer bool, devHostData string) {
	t.Helper()
	od, on, oc, oh := *flagDev, *flagNoTicket, *flagCustomer, *flagDevHostData
	*flagDev, *flagNoTicket, *flagCustomer, *flagDevHostData = dev, noticket, customer, devHostData
	t.Cleanup(func() { *flagDev, *flagNoTicket, *flagCustomer, *flagDevHostData = od, on, oc, oh })
}

func TestFlagRules(t *testing.T) {
	setFlags(t, true, true, true, "")
	if err := validateFlags(); err == nil || !strings.Contains(err.Error(), "-customer") || !strings.Contains(err.Error(), "-noticket") {
		t.Errorf("-customer with -noticket must be refused by name, got %v", err)
	}
	setFlags(t, false, false, true, strings.Repeat("ab", 32))
	if err := validateFlags(); err == nil || !strings.Contains(err.Error(), "-dev") {
		t.Errorf("-dev-host-data without -dev must be refused by name, got %v", err)
	}
	setFlags(t, true, false, true, "zz")
	if err := validateFlags(); err == nil {
		t.Error("a -dev-host-data that is not 64 hex characters was accepted")
	}
	setFlags(t, true, false, true, strings.Repeat("ab", 31))
	if err := validateFlags(); err == nil {
		t.Error("a 31-byte -dev-host-data was accepted")
	}
	setFlags(t, true, false, true, strings.Repeat("ab", 32))
	if err := validateFlags(); err != nil {
		t.Errorf("-dev -customer -dev-host-data with 32 bytes was refused: %v", err)
	}
	setFlags(t, false, false, false, "")
	if err := validateFlags(); err != nil {
		t.Errorf("the default flags were refused: %v", err)
	}
	setFlags(t, false, true, false, "")
	if err := validateFlags(); err != nil {
		t.Errorf("-noticket without -customer must stay as on main: %v", err)
	}
}

func TestHostDataSource(t *testing.T) {
	report := make([]byte, 0x2A0+144)
	for i := 0; i < 32; i++ {
		report[0xC0+i] = byte(i + 1)
	}
	got, err := hostDataFor(report, false, "")
	if err != nil || !bytes.Equal(got, report[0xC0:0xE0]) {
		t.Errorf("HOST_DATA must come from offset 0xC0 of the report: %x, %v", got, err)
	}
	if _, err := hostDataFor(report[:0xD0], false, ""); err == nil {
		t.Error("a short report gave a HOST_DATA")
	}
	if _, err := hostDataFor(nil, false, ""); err == nil {
		t.Error("no report outside -dev gave a HOST_DATA")
	}
	want := strings.Repeat("cd", 32)
	got, err = hostDataFor(nil, true, want)
	if err != nil || hex.EncodeToString(got) != want {
		t.Errorf("-dev with -dev-host-data: %x, %v", got, err)
	}
	if _, err := hostDataFor(report, false, want); err == nil {
		t.Error("-dev-host-data was used outside -dev")
	}
}

// Without -customer the first message, the ATTEST answer and the ticket check are what main has: same bytes, same decision.
func TestNonCustomerFirstMessageIsUnchanged(t *testing.T) {
	var open openMsg
	if err := json.Unmarshal([]byte(`{"target":"vnc","ticket":"T"}`), &open); err != nil || open.Target != "vnc" || open.Ticket != "T" || open.Customer != "" {
		t.Fatalf("an open message from today's client decoded as %+v, %v", open, err)
	}
	if got, _ := json.Marshal(openMsg{Target: "vnc", Ticket: "T"}); string(got) != `{"target":"vnc","ticket":"T"}` {
		t.Fatalf("the open message gained a field: %s", got)
	}
	r := newRig(t)
	if err := admit(r.box, openMsg{Target: "vnc", Ticket: r.sign(r.body(nil))}); err != nil || admit(r.box, openMsg{Target: "vnc", Ticket: ""}) == nil {
		t.Fatal("Cathedral ticket rules changed off customer mode")
	}
	r.box.seen = &seenTickets{used: map[[32]byte]int64{}}
	tk := r.sign(r.body(nil))
	if err := admit(r.box, openMsg{Target: "vnc", Ticket: tk}); err != nil {
		t.Fatal(err)
	}
	if err := admit(r.box, openMsg{Target: "vnc", Ticket: tk}); err == nil || err.Error() != "ticket refused" {
		t.Fatalf("a refusal off customer mode must read \"ticket refused\", got %v", err)
	}
}

func attestBytes(t *testing.T, box *boxState) string {
	t.Helper()
	srv, cli := net.Pipe()
	defer cli.Close()
	go serveStream(srv, box)
	if err := writeFrame(cli, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := readFrame(cli)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAttestAnswerIsUnchanged(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	box := &boxState{static: key, staticPub: pub, binding: []byte("B"), report: []byte("R"), certs: map[string][]byte{"vcek": []byte("V")}, seen: &seenTickets{used: map[[32]byte]int64{}}}
	want := `{"v":1,"static":"` + b64(pub) + `","binding":"B","report":"` + b64([]byte("R")) + `","certs":{"vcek":"` + b64([]byte("V")) + `"}}`
	if got := attestBytes(t, box); got != want {
		t.Fatalf("ATTEST off customer mode\n got %s\nwant %s", got, want)
	}
	box.customer, box.hostData = true, make([]byte, 32)
	if got := attestBytes(t, box); got != want {
		t.Fatalf("ATTEST in customer mode must carry the same fields\n got %s", got)
	}
	dev := &boxState{static: key, staticPub: pub, binding: []byte("B"), seen: &seenTickets{used: map[[32]byte]int64{}}}
	wantDev := `{"v":1,"static":"` + b64(pub) + `","binding":"B","report":"","dev":true}`
	if got := attestBytes(t, dev); got != wantDev {
		t.Fatalf("a dev box must say so in ATTEST\n got %s\nwant %s", got, wantDev)
	}
	dev.customer, dev.hostData = true, customerHostData(pub)
	if got := attestBytes(t, dev); got != wantDev {
		t.Fatalf("a dev box in customer mode must still say dev\n got %s", got)
	}
}
