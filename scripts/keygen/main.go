// Command keygen creates the ed25519 key pair that signs release checksums.
//
//	go run ./scripts/keygen PATH
//
// Writes the private key (base64 seed) to PATH with mode 0600 and prints the
// public key to paste into internal/update/pubkeys.go. Keep PATH outside the
// repository: store it in the PUSHWARDEN_SIGNING_KEY secret and an offline backup.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keygen PATH")
		os.Exit(2)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err) // never overwrite an existing key
		os.Exit(1)
	}
	fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed()))
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("private key written to", os.Args[1])
	fmt.Println("add to internal/update/pubkeys.go:")
	fmt.Printf("\t%q,\n", base64.StdEncoding.EncodeToString(pub))
}
