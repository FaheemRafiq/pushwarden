// Command sign writes FILE.sig: a base64 ed25519 signature of FILE made with the
// key in $THREATSCAN_SIGNING_KEY (base64 seed from scripts/keygen). It refuses a
// key whose public half is not in internal/update/pubkeys.go.
//
//	THREATSCAN_SIGNING_KEY=... go run ./scripts/sign dist/checksums.txt
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/update"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sign FILE")
		os.Exit(2)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("THREATSCAN_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "THREATSCAN_SIGNING_KEY must be the base64 seed from scripts/keygen")
		os.Exit(1)
	}
	msg, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
	// a release signed with a key the binaries do not trust could never self-update
	if err := update.VerifySignature(msg, sig, update.PublicKeys); err != nil {
		fmt.Fprintln(os.Stderr, "refusing to sign:", err, "(is THREATSCAN_SIGNING_KEY the key in internal/update/pubkeys.go?)")
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1]+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote", os.Args[1]+".sig")
}
