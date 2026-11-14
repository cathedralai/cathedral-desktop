package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Console lines go to stderr in dev mode; without this the tests would try to open /dev/ttyS0.
func TestMain(m *testing.M) {
	*flagDev = true
	os.Exit(m.Run())
}

type ticketRig struct {
	pub, static []byte
	priv        ed25519.PrivateKey
	box         *boxState
}

func newRig(t *testing.T) *ticketRig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	static := make([]byte, 32)
	if _, err := rand.Read(static); err != nil {
		t.Fatal(err)
	}
	return &ticketRig{pub: pub, static: static, priv: priv,
		box: &boxState{staticPub: static, ticketPub: pub, seen: &seenTickets{used: map[[32]byte]int64{}}}}
}

type ticketBody struct {
	Box    string `json:"box"`
	Target string `json:"target"`
	Exp    int64  `json:"exp"`
	Nonce  string `json:"nonce"`
}

func (r *ticketRig) body(mut func(*ticketBody)) ticketBody {
	b := ticketBody{Box: base64.StdEncoding.EncodeToString(r.static), Target: "vnc",
		Exp: time.Now().Unix() + 120, Nonce: "n" + base64.RawURLEncoding.EncodeToString(randBytes(8))}
	if mut != nil {
		mut(&b)
	}
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// sign builds a ticket the way mint_ticket.py does: body and signature, each base64url without padding.
func (r *ticketRig) sign(b ticketBody) string {
	raw, _ := json.Marshal(b)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(r.priv, raw))
}

func (r *ticketRig) open(ticket, target string) bool {
	return ticketOK(r.box, openMsg{Target: target, Ticket: ticket})
}

func TestValidTicketOpens(t *testing.T) {
	r := newRig(t)
	if !r.open(r.sign(r.body(nil)), "vnc") {
		t.Fatal("a valid ticket was refused")
	}
}

func TestTicketRefusals(t *testing.T) {
	r := newRig(t)
	now := time.Now().Unix()
	otherBox := base64.StdEncoding.EncodeToString(randBytes(32))
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged := func() string {
		raw, _ := json.Marshal(r.body(nil))
		return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherPriv, raw))
	}
	cases := []struct {
		name, ticket, target string
	}{
		{"wrong box", r.sign(r.body(func(b *ticketBody) { b.Box = otherBox })), "vnc"},
		{"wrong target", r.sign(r.body(func(b *ticketBody) { b.Target = "cdp" })), "vnc"},
		{"no nonce", r.sign(r.body(func(b *ticketBody) { b.Nonce = "" })), "vnc"},
		{"expiry too far ahead", r.sign(r.body(func(b *ticketBody) { b.Exp = now + 3600 })), "vnc"},
		{"expired", r.sign(r.body(func(b *ticketBody) { b.Exp = now - 5 })), "vnc"},
		{"wrong signer", forged(), "vnc"},
		{"no dot", "abcdef", "vnc"},
		{"three parts", "a.b.c", "vnc"},
		{"not base64", "!!!.???", "vnc"},
		{"short signature", base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." + base64.RawURLEncoding.EncodeToString([]byte("short")), "vnc"},
	}
	for _, c := range cases {
		if r.open(c.ticket, c.target) {
			t.Errorf("%s: ticket was accepted", c.name)
		}
	}
	if len(r.box.seen.used) != 0 {
		t.Errorf("refused tickets were remembered: %d entries", len(r.box.seen.used))
	}
}

func TestReplayRefused(t *testing.T) {
	r := newRig(t)
	tk := r.sign(r.body(nil))
	if !r.open(tk, "vnc") {
		t.Fatal("first use refused")
	}
	if r.open(tk, "vnc") {
		t.Fatal("second use of the same ticket was accepted")
	}
}

func TestExpiredEntriesDropped(t *testing.T) {
	r := newRig(t)
	stale := [32]byte{1}
	r.box.seen.used[stale] = time.Now().Unix() - 10
	if !r.open(r.sign(r.body(nil)), "vnc") {
		t.Fatal("valid ticket refused")
	}
	if _, kept := r.box.seen.used[stale]; kept {
		t.Error("an expired entry stayed in the used table")
	}
}

func TestParallelUseHasOneWinner(t *testing.T) {
	r := newRig(t)
	tk := r.sign(r.body(nil))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.open(tk, "vnc") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d of 64 simultaneous uses won, want 1", wins.Load())
	}
}

func TestEmptyTicketNeedsNoTicketFlag(t *testing.T) {
	r := newRig(t)
	defer func(old bool) { *flagNoTicket = old }(*flagNoTicket)
	*flagNoTicket = false
	if r.open("", "vnc") {
		t.Error("empty ticket accepted without -noticket")
	}
	*flagNoTicket = true
	if !r.open("", "vnc") {
		t.Error("empty ticket refused with -noticket")
	}
}

func TestNoPinnedKeyRefusesEverything(t *testing.T) {
	r := newRig(t)
	tk := r.sign(r.body(nil))
	r.box.ticketPub = nil
	if r.open(tk, "vnc") {
		t.Error("ticket accepted by a box with no pinned key")
	}
}
