// Command threatscan detects, removes and blocks the PolinRider / Contagious
// Interview supply-chain malware on developer machines.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// version is set at build time: -ldflags "-X main.version=0.1.0"
var version = "0.2.1-dev"

type command struct {
	name, help string
	run        func(args []string) int
}

var commands []command

func register(name, help string, run func([]string) int) {
	commands = append(commands, command{name, help, run})
}

func usage() {
	fmt.Println("ThreatScan " + version + " - PolinRider / Contagious Interview protection\n")
	fmt.Println("Usage: threatscan <command> [options]\n\nCommands:")
	order := map[string]int{"scan": 0, "status": 1, "history": 2, "guard": 3, "install": 4, "uninstall": 5, "update": 6, "update-iocs": 7}
	sorted := append([]command{}, commands...)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi, ok1 := order[sorted[i].name]
		oj, ok2 := order[sorted[j].name]
		if !ok1 {
			oi = 100
		}
		if !ok2 {
			oj = 100
		}
		return oi < oj
	})
	for _, c := range sorted {
		fmt.Printf("  %-13s %s\n", c.name, c.help)
	}
	fmt.Println("\nRun `threatscan <command> -h` for options, `threatscan help <command>` for the full documentation.")
	fmt.Println("`threatscan [dirs]` is short for `threatscan scan [dirs]`.")
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "__askpass": // git credential helper used by github-clean; not a user command
			return askpass(args[1:])
		case "-h", "--help", "help":
			return cmdHelp(args[1:])
		case "--version", "-version":
			args[0] = "version"
		}
		for _, c := range commands {
			if c.name == args[0] {
				return c.run(args[1:])
			}
		}
	}
	// Backwards compatible: `threatscan [opts] [dirs]` means `threatscan scan ...`
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if st, err := os.Stat(args[0]); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
			usage()
			return 2
		}
	}
	return cmdScan(args)
}
