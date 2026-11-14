package main

// Customer mode (AB#353 WP3). The host launches the box with HOST_DATA = sha256("cathedral-tee-customer/v1\0" || customer
// public key), a field of the attestation report that the chip signs and the host cannot change after launch. In this mode
// the box opens a stream only for the key that hash names: the client sends the key in message 1, the box hashes it and
// compares it with its own HOST_DATA, then checks the ticket against that same key. Cathedral's ticket key is never used.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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
	if open.Customer == "" {
		return errors.New("customer mode: the open message has no customer key")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(open.Customer)
	if err != nil || len(pub) != 32 {
		return errors.New("customer mode: the customer key must be 32 bytes, unpadded base64url")
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

// Stubs for the review fixes (red step).
func weakCustomerKey(pub []byte) bool { return false }

func readyMessage(box *boxState) []byte { return []byte(`{"ok":true}`) }
