package main

// Customer mode (AB#353 WP3). The host launches the box with HOST_DATA = sha256("cathedral-tee-customer/v1\0" || customer
// public key), a field of the attestation report that the chip signs and the host cannot change after launch. In this mode
// the box opens a stream only for the key that hash names: the client sends the key in message 1, the box hashes it and
// compares it with its own HOST_DATA, then checks the ticket against that same key. Cathedral's ticket key is never used.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
)

var (
	flagCustomer    = flag.Bool("customer", false, "customer mode: open only for the key whose labelled hash is this box's HOST_DATA")
	flagDevHostData = flag.String("dev-host-data", "", "with -dev only: HOST_DATA as 64 hex characters, in place of the one in the report")
)

const (
	customerDomain  = "cathedral-tee-customer/v1\x00" // the zero byte is part of the label
	hostDataLen     = 32
	hostDataOffset  = 0xC0
	reportSignedLen = 0x2A0
)

var errTicketRefused = errors.New("ticket refused")

// validateFlags refuses flag combinations that would weaken customer mode.
func validateFlags() error {
	if *flagCustomer && *flagNoTicket {
		return errors.New("-customer and -noticket cannot be used together: customer mode always needs a ticket")
	}
	if *flagDevHostData != "" {
		if !*flagCustomer {
			return errors.New("-dev-host-data needs -customer: it only sets the HOST_DATA that customer mode compares")
		}
		if !*flagDev {
			return errors.New("-dev-host-data needs -dev: outside it, HOST_DATA comes from the attestation report")
		}
		if _, err := parseDevHostData(*flagDevHostData); err != nil {
			return err
		}
	}
	return nil
}

func parseDevHostData(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != hostDataLen {
		return nil, errors.New("-dev-host-data must be 64 hex characters (32 bytes)")
	}
	return b, nil
}

// customerHostData is the launch value for one customer key.
func customerHostData(pub []byte) []byte {
	sum := sha256.Sum256(append([]byte(customerDomain), pub...))
	return sum[:]
}

// checkCustomerHostData compares all 32 bytes in constant time. A zero value never matches a key.
func checkCustomerHostData(hostData, pub []byte) error {
	if len(pub) != 32 {
		return errors.New("customer mode: the customer key is not 32 bytes")
	}
	if weakCustomerKey(pub) {
		return errors.New("customer mode: this customer key is not a usable key (small-order or non-canonical point)")
	}
	if len(hostData) != hostDataLen {
		return fmt.Errorf("customer mode: HOST_DATA is %d bytes, expected %d", len(hostData), hostDataLen)
	}
	want := customerHostData(pub)
	var zero byte
	for _, b := range hostData {
		zero |= b
	}
	match := subtle.ConstantTimeCompare(hostData, want)
	if zero == 0 {
		return errors.New("customer mode: this box's HOST_DATA is zero, so it was not launched for a customer key")
	}
	if match != 1 {
		return errors.New("customer mode: the key does not match this box's HOST_DATA")
	}
	return nil
}

// hostDataFor reads the box's own HOST_DATA from its attestation report. Only a -dev box, which has no report, may take it from -dev-host-data.
func hostDataFor(report []byte, dev bool, devHex string) ([]byte, error) {
	if devHex != "" && !dev {
		return nil, errors.New("-dev-host-data needs -dev")
	}
	if dev && report == nil {
		if devHex == "" {
			return nil, errors.New("a -dev box has no report: give -dev-host-data")
		}
		return parseDevHostData(devHex)
	}
	if len(report) < reportSignedLen {
		return nil, errors.New("no attestation report to read HOST_DATA from")
	}
	return append([]byte(nil), report[hostDataOffset:hostDataOffset+hostDataLen]...), nil
}

// admit decides whether a client may open a stream. Off customer mode it is the Cathedral ticket check, unchanged.
// In customer mode nothing falls back to that check.
func admit(box *boxState, open openMsg) error {
	if !box.customer {
		if ticketOK(box, open) {
			return nil
		}
		return errTicketRefused
	}
	// A box that cannot name a HOST_DATA, or whose HOST_DATA is zero, was not launched for a customer key: say so before anything else.
	if len(box.hostData) != hostDataLen || bytes.Equal(box.hostData, make([]byte, hostDataLen)) {
		return errors.New("customer mode: this box was not launched for a customer key (its HOST_DATA is zero or missing)")
	}
	if open.Customer == "" {
		return errors.New("customer mode: the open message has no customer key")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(open.Customer)
	if err != nil || len(pub) != 32 {
		return errors.New("customer mode: the customer key must be 32 bytes, unpadded base64url")
	}
	if weakCustomerKey(pub) {
		return errors.New("customer mode: this customer key is not a usable key (small-order or non-canonical point)")
	}
	if err := checkCustomerHostData(box.hostData, pub); err != nil {
		return err
	}
	if open.Ticket == "" {
		return errTicketRefused
	}
	exp, id, ok := verifyTicket(pub, open.Ticket, open.Target, box.staticPub)
	if !ok || !box.seen.use(id, exp) {
		return errTicketRefused
	}
	return nil
}

// weakCustomerKey reports a small-order or non-canonical Ed25519 point. For such a key a ticket verifies with no private key.
// The sign bit is ignored, so a small-order point is caught whichever sign it is written with.
func weakCustomerKey(pub []byte) bool {
	if len(pub) != 32 {
		return true
	}
	c := append([]byte(nil), pub...)
	c[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse(c))
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	if y.Cmp(p) >= 0 {
		return true
	}
	for _, w := range weakY {
		if y.Cmp(w) == 0 {
			return true
		}
	}
	return false
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// y values of the points of order dividing 8: 0, 1, p-1 and the two of order 8 (given as little-endian hex).
var weakY = func() []*big.Int {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	ys := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1))}
	for _, h := range []string{"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"} {
		b, _ := hex.DecodeString(h)
		ys = append(ys, new(big.Int).SetBytes(reverse(b)))
	}
	return ys
}()

// readyMessage is message 2's plaintext. Off customer mode it is exactly what main sends; in customer mode it adds a marker, inside
// the same authenticated answer, so a client holding a customer key can tell the box is in customer mode.
func readyMessage(box *boxState) []byte {
	if box.customer {
		return []byte(`{"ok":true,"mode":"customer"}`)
	}
	return []byte(`{"ok":true}`)
}
