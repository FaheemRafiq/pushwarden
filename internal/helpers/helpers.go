// Package helpers holds file classification and evidence logic shared by scanners and protect.
package helpers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/FaheemRafiq/pushwarden/internal/iocs"
)

type magic struct {
	off int
	sig []byte
}

var FontExt = map[string]bool{".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true}

var AssetMagic = map[string][]magic{
	".woff2": {{0, []byte("wOF2")}},
	".woff":  {{0, []byte("wOFF")}},
	".ttf":   {{0, []byte{0, 1, 0, 0}}, {0, []byte("true")}, {0, []byte("OTTO")}, {0, []byte("ttcf")}},
	".otf":   {{0, []byte("OTTO")}, {0, []byte{0, 1, 0, 0}}},
	".eot":   {{34, []byte("LP")}},
	".png":   {{0, []byte("\x89PNG")}},
	".jpg":   {{0, []byte{0xff, 0xd8, 0xff}}},
	".jpeg":  {{0, []byte{0xff, 0xd8, 0xff}}},
	".gif":   {{0, []byte("GIF87a")}, {0, []byte("GIF89a")}},
	".ico":   {{0, []byte{0, 0, 1, 0}}, {0, []byte{0, 0, 2, 0}}},
	".webp":  {{0, []byte("RIFF")}},
}

var TextAssetExt = map[string]bool{".dict": true}

var ScriptExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields(".js .mjs .cjs .ts .tsx .jsx .mts .cts .json .jsonc .php .py .sh .bash .zsh .bat .cmd .ps1 .vbs .html .htm .env .yml .yaml .toml .txt .md") {
		ScriptExt[e] = true
	}
}

var JSExt = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".mts": true, ".cts": true, ".html": true, ".htm": true}

const AllowToken = "pushwarden:allow-signatures"

var codeMarkers = [][]byte{[]byte("<html"), []byte("<!doc"), []byte("<script"), []byte("require("), []byte("global["),
	[]byte("global."), []byte("function"), []byte("eval("), []byte("const "), []byte("var "), []byte("let "),
	[]byte("#!/"), []byte("process.env"), []byte("=>")}

var skipDirs = map[string]bool{}

func init() {
	for _, d := range []string{"node_modules", ".git", ".hg", ".svn", "vendor", "__pycache__", ".venv", "venv", "dist", "build",
		".next", ".nuxt", ".cache", "target", ".gradle", ".idea", ".pushwarden",
		"google-chrome", "chromium", "BraveSoftware", "microsoft-edge", "Google", "Mozilla", "firefox", "Extensions",
		"Service Worker", "Cache", "Code Cache", "GPUCache", "IndexedDB", "Local Storage"} {
		skipDirs[d] = true
	}
}

func SkipDir(name string) bool { return skipDirs[name] }

// IsUnder reports whether path equals or lies inside any root (component aware).
func IsUnder(path string, roots []string) bool {
	p := clean(path)
	for _, r := range roots {
		rr := clean(expand(r))
		if rr == "" {
			continue
		}
		if p == rr || strings.HasPrefix(p, rr+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// clean makes p absolute and resolves symlinks (and Windows short names) on
// the longest prefix that exists, so a path that does not exist yet still
// compares equal to its resolved root (/var/x vs /private/var/x on macOS).
func clean(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		a = p
	}
	a = filepath.Clean(a)
	rest := ""
	for cur := a; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Clean(filepath.Join(r, rest))
		}
		parent, base := filepath.Dir(cur), filepath.Base(cur)
		if parent == cur || base == "" {
			return a
		}
		rest = filepath.Join(base, rest)
		cur = parent
	}
}

func expand(p string) string {
	if strings.HasPrefix(p, "~") {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, p[1:])
	}
	return p
}

func Expand(p string) string { return expand(p) }

func SHA256(path string) string {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > 50<<20 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ReadText reads up to limit bytes of a file as text ("" if larger or unreadable).
func ReadText(path string, limit int64) string {
	b := ReadBytes(path, limit)
	return string(b)
}

func ReadBytes(path string, limit int64) []byte {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > limit {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func head(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	k, _ := io.ReadFull(f, buf)
	return buf[:k]
}

// AssetVerdict classifies a font/image/dict file by content:
// "real", "code" (script/markup payload), "text" or "unknown".
// Leading whitespace padding is skipped before looking for code.
func AssetVerdict(path string, marker *regexp.Regexp) (string, string) {
	h := head(path, 8192)
	if h == nil {
		return "unknown", ""
	}
	if len(h) == 0 {
		return "text", "file is empty"
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, m := range AssetMagic[ext] {
		if len(h) >= m.off+len(m.sig) && bytes.Equal(h[m.off:m.off+len(m.sig)], m.sig) {
			return "real", ""
		}
	}
	if bytes.HasPrefix(h, []byte("version https://git-lfs")) {
		return "real", ""
	}
	body := bytes.TrimLeft(h, " \t\r\n\f\v")
	pad := len(h) - len(body)
	padNote := ""
	if pad >= 32 {
		padNote = fmt.Sprintf(" after %d bytes of whitespace padding", pad)
	}
	low := bytes.ToLower(body[:min(len(body), 2048)])
	for _, cm := range codeMarkers {
		if bytes.Contains(low, cm) {
			d := "JavaScript/HTML" + padNote
			if m := marker.Find(body); m != nil {
				d += "; campaign marker: " + trunc(string(m), 60)
			}
			return "code", d
		}
	}
	if TextAssetExt[ext] {
		return "real", ""
	}
	if !bytes.Contains(h, []byte{0}) && utf8.Valid(h) {
		return "text", "plain text" + padNote
	}
	return "unknown", ""
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func Trunc(s string, n int) string { return trunc(s, n) }

// IsAllowlisted: rule sets/tests may opt out with AllowToken in their first 512 bytes.
// Never honoured for config, entry, font-name, asset or JS/TS files.
func IsAllowlisted(path string, i *iocs.IOCs) bool {
	name := filepath.Base(path)
	if i.IsConfig(name) || i.IsEntry(name) || i.IsFontName(name) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := AssetMagic[ext]; ok || TextAssetExt[ext] || JSExt[ext] {
		return false
	}
	return bytes.Contains(head(path, 512), []byte(AllowToken))
}

var padRe = regexp.MustCompile(`[ \t]{40,}\S`)

// Evidence lists the concrete indicators found in content.
func Evidence(content string, i *iocs.IOCs, limit int) []string {
	var ev []string
	add := func(s string) { ev = append(ev, s) }
	for _, s := range i.LiteralSignatures {
		if strings.Contains(content, s) {
			add(fmt.Sprintf("literal signature %q", s))
		}
	}
	for _, loc := range i.Marker.FindAllStringIndex(content, limit) {
		add(fmt.Sprintf("campaign marker %q at offset %d", trunc(content[loc[0]:loc[1]], 60), loc[0]))
	}
	for _, k := range i.XorKeys {
		if strings.Contains(content, k) {
			add(fmt.Sprintf("payload XOR key %q", k))
		}
	}
	low := strings.ToLower(content)
	for _, w := range i.Wallets {
		if strings.Contains(low, strings.ToLower(w)) {
			add("dead-drop wallet " + trunc(w, 14) + "...")
		}
	}
	for _, h := range i.MaliciousHosts {
		if strings.Contains(content, h) {
			add("C2 host " + h)
		}
	}
	for _, ip := range i.MaliciousIPs {
		if strings.Contains(content, ip) {
			add("C2 IP " + ip)
		}
	}
	if strings.Contains(content, "http") {
		for _, p := range i.C2URLPaths {
			if strings.Contains(content, p) {
				add("C2 path " + p)
			}
		}
	}
	for _, t := range i.TelegramIndicators {
		if strings.Contains(content, t) {
			add("Telegram exfiltration bot id")
			break
		}
	}
	if m := padRe.FindString(content); m != "" {
		add(fmt.Sprintf("%d whitespace characters hiding code on one line", len(m)-1))
	}
	seen := map[string]bool{}
	out := ev[:0:0]
	for _, e := range ev {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

var pad32 = regexp.MustCompile(`[ \t]{32,}`)

// PayloadCut returns the offset where an appended payload starts, or -1.
func PayloadCut(content string, i *iocs.IOCs) int {
	idx := -1
	if loc := i.Marker.FindStringIndex(content); loc != nil {
		idx = loc[0]
	}
	for _, s := range append(append([]string{}, i.LiteralSignatures...), i.XorKeys...) {
		if j := strings.Index(content, s); j != -1 && (idx == -1 || j < idx) {
			idx = j
		}
	}
	if idx == -1 {
		return -1
	}
	lineStart := strings.LastIndex(content[:idx], "\n") + 1
	if loc := pad32.FindStringIndex(content[lineStart:idx]); loc != nil {
		return lineStart + loc[0]
	}
	return lineStart
}
