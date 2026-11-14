package main

// Stubs for the red step of AB#353 WP3: the names and signatures the tests use, with no behaviour yet.

import "flag"

var (
	flagCustomer    = flag.Bool("customer", false, "customer mode: open only for the key whose hash is this box's HOST_DATA")
	flagDevHostData = flag.String("dev-host-data", "", "development only: HOST_DATA as 64 hex characters, in place of the report's")
)

func validateFlags() error { return nil }

func customerHostData(pub []byte) []byte { return make([]byte, 32) }

func checkCustomerHostData(hostData, pub []byte) error { return nil }

func hostDataFor(report []byte, dev bool, devHex string) ([]byte, error) { return nil, nil }

func admit(box *boxState, open openMsg) error {
	if ticketOK(box, open) {
		return nil
	}
	return errNotImplemented
}

var errNotImplemented = errString("not implemented")

type errString string

func (e errString) Error() string { return string(e) }
