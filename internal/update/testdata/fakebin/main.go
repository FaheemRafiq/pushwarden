// Command fakebin stands in for a released pushwarden binary in update tests.
package main

import (
	"fmt"
	"os"
)

var (
	version = "0.0.0"
	broken  = "" // non-empty: fail the `version` self-test
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if broken != "" {
			fmt.Println("crashed")
			os.Exit(3)
		}
		fmt.Println("PushWarden " + version)
	}
}
