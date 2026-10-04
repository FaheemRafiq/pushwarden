package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/FaheemRafiq/pushwarden/docs"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

func init() {
	register("help", "full documentation: pushwarden help <command|topic>", cmdHelp)
}

func cmdHelp(args []string) int {
	u := ui.New(false, false)
	if len(args) == 0 {
		usage()
		return 0
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Print("Usage: pushwarden help <command|topic>\n\n")
		helpTopics(u)
		return 0
	}
	if args[0] == "all" {
		return page(docs.Render(docs.CLI, termWidth(), style(u)))
	}
	t, ok := docs.Lookup(args[0])
	if !ok {
		fmt.Fprintf(os.Stderr, "no documentation for %q\n\n", args[0])
		helpTopics(u)
		return 2
	}
	md := "# " + t.Title + "\n\n" + t.Body
	return page(docs.Render(md, termWidth(), style(u)))
}

func helpTopics(u *ui.UI) {
	cmds, refs := docs.Names()
	fmt.Println(u.C("BOLD", "Commands:  ") + strings.Join(cmds, ", "))
	fmt.Println(u.C("BOLD", "Topics:    ") + strings.Join(refs, ", ") + ", all")
	fmt.Println("\nExamples: pushwarden help install     pushwarden help github-clean     pushwarden help config-keys")
}

func style(u *ui.UI) docs.Style {
	return func(kind, s string) string {
		switch kind {
		case "heading":
			return u.C("BOLD", s)
		case "label":
			return u.C("BOLD_CYAN", s)
		case "code":
			return u.C("DIM", s)
		}
		return s
	}
}

func termWidth() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 40 {
		return min(c, 100)
	}
	if out, err := exec.Command("tput", "cols").Output(); err == nil {
		if c, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && c > 40 {
			return min(c, 100)
		}
	}
	return 80
}

// page shows long output through the pager when on a terminal, like git and man.
func page(text string) int {
	st, err := os.Stdout.Stat()
	tty := err == nil && st.Mode()&os.ModeCharDevice != 0
	if tty && strings.Count(text, "\n") > 40 && os.Getenv("PUSHWARDEN_NO_PAGER") == "" {
		pager := os.Getenv("PAGER")
		if pager == "" {
			pager = "less"
		}
		if p, err := exec.LookPath(strings.Fields(pager)[0]); err == nil {
			cmd := exec.Command(p, strings.Fields(pager)[1:]...)
			if strings.HasSuffix(p, "less") {
				cmd.Args = append(cmd.Args, "-FRX")
			}
			cmd.Stdin = strings.NewReader(text)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if cmd.Run() == nil {
				return 0
			}
		}
	}
	fmt.Print(text)
	return 0
}
