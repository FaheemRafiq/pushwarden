package docs

import (
	"strings"
	"testing"
)

func TestTopicsAndLookup(t *testing.T) {
	for _, name := range []string{"scan", "github-clean", "install", "history", "restore", "alerts", "config-keys", "env", "troubleshooting", "HELP-less"} {
		tp, ok := Lookup(name)
		if name == "HELP-less" {
			if ok {
				t.Fatal("unknown topic resolved")
			}
			continue
		}
		if !ok || tp.Body == "" {
			t.Fatalf("topic %q missing or empty", name)
		}
	}
	if tp, _ := Lookup("restore"); tp.Name != "history" {
		t.Fatalf("restore should alias history, got %q", tp.Name)
	}
	cmds, refs := Names()
	if len(cmds) < 14 || len(refs) < 6 {
		t.Fatalf("commands=%v refs=%v", cmds, refs)
	}
	if tp, _ := Lookup("github-clean"); !strings.Contains(tp.Body, "--apply") {
		t.Fatal("github-clean body should mention --apply")
	}
}

func TestRender(t *testing.T) {
	md := "# Title\n\nSome **bold** and `code` and a [link](#x) plus [ext](https://e.x).\n\n" +
		"| Option | Effect |\n|---|---|\n| `--a` | first thing that is quite long and needs to wrap around the width limit |\n| `--b` | second |\n\n" +
		"```\npushwarden scan\n```\n\n- item one\n1. step one\n"
	out := Render(md, 60, nil)
	for _, want := range []string{"Title", "Some bold and code and a link plus ext (https://e.x).", "--a", "--b", "second", "    pushwarden scan", "  - item one", "  1. step one"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 60 {
			t.Errorf("line too long: %q", l)
		}
	}
	if strings.Contains(out, "|") || strings.Contains(out, "**") || strings.Contains(out, "`") {
		t.Errorf("markdown leaked:\n%s", out)
	}
	if strings.Contains(Render(CLI, 80, nil), "|---") {
		t.Error("table separators leaked in the full document")
	}
}
