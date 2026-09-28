package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
)

type ctx struct {
	P       *platform.Info
	DataDir string
	Cfg     *config.Config
	I       *iocs.IOCs
}

func newCtx() (*ctx, error) {
	p := platform.New()
	d := p.DataDir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	i, err := iocs.Load(d)
	if err != nil {
		return nil, err
	}
	return &ctx{P: p, DataDir: d, Cfg: config.Load(d), I: i}, nil
}

func mustCtx() *ctx {
	c, err := newCtx()
	if err != nil {
		fmt.Fprintln(os.Stderr, "threatscan:", err)
		os.Exit(2)
	}
	return c
}

// newFlags builds a FlagSet that accepts both -flag and --flag (stdlib does) and
// lets flags appear after positional args, like argparse.
func newFlags(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: threatscan %s %s\n\nOptions:\n", name, usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseInterspersed parses flags that may be mixed with positional args.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func absDirs(in []string) ([]string, error) {
	var out []string
	for _, d := range in {
		if strings.HasPrefix(d, "~") {
			h, _ := os.UserHomeDir()
			d = filepath.Join(h, d[1:])
		}
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() {
			return nil, fmt.Errorf("not a directory: %s", d)
		}
		a, _ := filepath.Abs(d)
		out = append(out, a)
	}
	return out, nil
}

func isTTY() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
