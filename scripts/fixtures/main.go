// Command fixtures writes the inert test repositories to a directory:
//
//	go run ./scripts/fixtures DIR
package main

import (
	"fmt"
	"os"

	"github.com/FaheemRafiq/pushwarden/internal/testfixtures"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fixtures DIR")
		os.Exit(2)
	}
	if err := testfixtures.Build(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
