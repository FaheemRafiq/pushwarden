package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The documentation site (GitHub Pages, this folder) is checked here so a
// broken link, a page missing from the navigation or a stale llms file fails
// the build. Regenerate llms.txt and llms-full.txt after editing pages:
//
//	UPDATE_SITE=1 go test ./docs -run TestSite

const (
	siteURL = "https://faheemrafiq.github.io/threatscan"
	rawURL  = "https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/docs"
)

type sitePage struct {
	section, title, url string // from _data/nav.yml
	file                string // the Markdown source in this folder
	desc, body          string // from the file: front-matter description, text after the front matter
}

var (
	navSection = regexp.MustCompile(`^- section: (.+)$`)
	navTitle   = regexp.MustCompile(`^\s+- title: (.+)$`)
	navURL     = regexp.MustCompile(`^\s+url: (/.+\.html)$`)
	fmDesc     = regexp.MustCompile(`(?m)^description: "(.+)"$`)
	fmTitle    = regexp.MustCompile(`(?m)^title: (.+)$`)
	mdLink     = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

func loadSite(t *testing.T) []sitePage {
	t.Helper()
	nav, err := os.ReadFile(filepath.Join("_data", "nav.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var pages []sitePage
	section, title := "", ""
	for _, l := range strings.Split(string(nav), "\n") {
		if m := navSection.FindStringSubmatch(l); m != nil {
			section = m[1]
		} else if m := navTitle.FindStringSubmatch(l); m != nil {
			title = m[1]
		} else if m := navURL.FindStringSubmatch(l); m != nil {
			p := sitePage{section: section, title: title, url: m[1]}
			p.file = strings.TrimSuffix(strings.TrimPrefix(m[1], "/"), ".html") + ".md"
			raw, err := os.ReadFile(filepath.FromSlash(p.file))
			if err != nil {
				t.Fatalf("navigation entry %q: %v", title, err)
			}
			parts := strings.SplitN(string(raw), "---\n", 3)
			if len(parts) != 3 || parts[0] != "" {
				t.Fatalf("%s: front matter missing", p.file)
			}
			d := fmDesc.FindStringSubmatch(parts[1])
			ft := fmTitle.FindStringSubmatch(parts[1])
			if d == nil || ft == nil {
				t.Fatalf("%s: front matter needs `title:` and a double-quoted `description:`", p.file)
			}
			if ft[1] != title {
				t.Errorf("%s: title %q differs from the navigation title %q", p.file, ft[1], title)
			}
			p.desc, p.body = d[1], strings.TrimLeft(parts[2], "\n")
			pages = append(pages, p)
		}
	}
	if len(pages) < 15 {
		t.Fatalf("only %d pages found in the navigation", len(pages))
	}
	return pages
}

func TestSitePagesAreConsistent(t *testing.T) {
	pages := loadSite(t)
	inNav := map[string]bool{}
	for _, p := range pages {
		inNav[p.file] = true
		if p.file == "reference.md" {
			continue // includes CLI.md, checked by the other tests in this package
		}
		if !strings.HasPrefix(p.body, "# ") {
			t.Errorf("%s: the text must start with a level-1 heading", p.file)
		}
		// Jekyll runs Liquid over every page: these sequences would be executed, not shown
		if strings.Contains(p.body, "{{") || strings.Contains(p.body, "{%") {
			t.Errorf("%s: contains Liquid syntax ({{ or {%%)", p.file)
		}
		for _, m := range mdLink.FindAllStringSubmatch(p.body, -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target, _, _ = strings.Cut(target, "#")
			if !strings.HasSuffix(target, ".md") {
				t.Errorf("%s: relative link %q should point at a .md page", p.file, m[1])
				continue
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.FromSlash(p.file)), filepath.FromSlash(target))); err != nil {
				t.Errorf("%s: broken link %q", p.file, m[1])
			}
		}
	}
	guides, _ := filepath.Glob(filepath.Join("guide", "*.md"))
	for _, g := range guides {
		if !inNav[filepath.ToSlash(g)] {
			t.Errorf("%s is not in _data/nav.yml", g)
		}
	}
	if strings.Contains(CLI, "{{") || strings.Contains(CLI, "{%") {
		t.Error("CLI.md contains Liquid syntax; reference.md includes it through Jekyll")
	}
}

// llms builds llms.txt (the index) and llms-full.txt (everything in one file).
func llms(pages []sitePage) (index, full string) {
	var a, b strings.Builder
	a.WriteString("# ThreatScan\n\n" +
		"> ThreatScan is a free, open-source tool that protects developer machines and GitHub repositories from the " +
		"PolinRider / Contagious Interview supply-chain malware. It is a single program for Linux, macOS and Windows: " +
		"a background guard with real-time file protection, an on-demand scanner, a C2 firewall block, editor hardening, " +
		"and a command that cleans every branch of every GitHub repository you can push to.\n\n" +
		"Every feature is a subcommand of `threatscan`. It installs per user without administrator rights, every destructive " +
		"action is reversible through a quarantine, and nothing leaves the machine unless the user opts in. " +
		"The links below are Markdown sources. The same pages are rendered at " + siteURL + "/guide/overview.html, " +
		"and the whole documentation is one file at " + siteURL + "/llms-full.txt.\n")
	b.WriteString("<!-- threatscan:allow-signatures -->\n# ThreatScan documentation\n\n" +
		"This file is the complete ThreatScan documentation in one plain-text Markdown file, generated from the pages at " +
		siteURL + "/. Each page starts with a level-1 heading and a `Source:` line.\n")
	section := ""
	for _, p := range pages {
		if p.section != section {
			section = p.section
			a.WriteString("\n## " + section + "\n\n")
		}
		src, body := p.file, p.body
		if p.file == "reference.md" {
			src, body = "CLI.md", strings.TrimPrefix(CLI, "<!-- threatscan:allow-signatures -->\n")
		}
		a.WriteString("- [" + p.title + "](" + rawURL + "/" + src + "): " + p.desc + "\n")
		head, rest, _ := strings.Cut(strings.TrimSpace(body), "\n")
		b.WriteString("\n\n---\n\n" + head + "\n\nSource: " + siteURL + p.url + "\n" + rest + "\n")
	}
	a.WriteString("\n## Optional\n\n" +
		"- [Whole documentation in one file](" + siteURL + "/llms-full.txt): every page above, concatenated\n" +
		"- [Indicator file](https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/threatscan/iocs.json): every signature, key, hash and C2 address the scanner uses\n" +
		"- [Supabase table definition](" + rawURL + "/supabase.sql): the SQL for the optional central event upload\n" +
		"- [Source code](https://github.com/FaheemRafiq/threatscan): the repository\n")
	return a.String(), b.String()
}

func TestSiteLLMSFilesAreCurrent(t *testing.T) {
	index, full := llms(loadSite(t))
	for name, want := range map[string]string{"llms.txt": index, "llms-full.txt": full} {
		if os.Getenv("UPDATE_SITE") != "" {
			if err := os.WriteFile(name, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, _ := os.ReadFile(name)
		if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
			t.Errorf("%s is out of date; run: UPDATE_SITE=1 go test ./docs -run TestSite", name)
		}
	}
}
