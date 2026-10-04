// pushwarden:allow-signatures
package helpers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/pushwarden/internal/iocs"
)

const CleanPostcss = "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};\n"

var InfectedPostcss = "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};" + strings.Repeat(" ", 280) +
	"global['_V']='8-st17';(function(){var MDy=function(){return 'inert'};})();\n"

func load(t *testing.T) *iocs.IOCs {
	i, err := iocs.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestAssetVerdict(t *testing.T) {
	i := load(t)
	d := t.TempDir()
	real := filepath.Join(d, "a.woff2")
	os.WriteFile(real, append([]byte("wOF2"), make([]byte, 50)...), 0o644)
	if v, _ := AssetVerdict(real, i.Marker); v != "real" {
		t.Fatal(v)
	}
	fake := filepath.Join(d, "fa-solid-900.woff2")
	os.WriteFile(fake, []byte(strings.Repeat(" ", 300)+"var x = require('y');"), 0o644)
	v, det := AssetVerdict(fake, i.Marker)
	if v != "code" || !strings.Contains(det, "padding") {
		t.Fatal(v, det)
	}
	nopad := filepath.Join(d, "b.woff2")
	os.WriteFile(nopad, []byte("const a = () => 1;"), 0o644)
	if v, _ := AssetVerdict(nopad, i.Marker); v != "code" {
		t.Fatal(v)
	}
}

func TestPayloadCut(t *testing.T) {
	i := load(t)
	cut := PayloadCut(InfectedPostcss, i)
	if cut <= 0 || strings.TrimRight(InfectedPostcss[:cut], " \n") != strings.TrimRight(CleanPostcss, " \n") {
		t.Fatalf("cut=%d %q", cut, InfectedPostcss[:max(cut, 0)])
	}
	if PayloadCut(CleanPostcss, i) != -1 {
		t.Fatal("clean should not cut")
	}
}

func TestEvidenceAndAllowlist(t *testing.T) {
	i := load(t)
	ev := Evidence(InfectedPostcss, i, 12)
	var hasMarker, hasPad bool
	for _, e := range ev {
		hasMarker = hasMarker || strings.Contains(e, "campaign marker")
		hasPad = hasPad || strings.Contains(e, "whitespace")
	}
	if !hasMarker || !hasPad {
		t.Fatal(ev)
	}
	d := t.TempDir()
	db := filepath.Join(d, "rules.yaml")
	os.WriteFile(db, []byte("# "+AllowToken+"\nglobal['_V']='A4-1928'\n"), 0o644)
	if !IsAllowlisted(db, i) {
		t.Fatal("yaml should be allowlisted")
	}
	js := filepath.Join(d, "x.js")
	os.WriteFile(js, []byte("// "+AllowToken+"\n"), 0o644)
	if IsAllowlisted(js, i) {
		t.Fatal("js must never be allowlisted")
	}
	if !IsUnder(filepath.Join(d, "vendor", "x"), []string{filepath.Join(d, "vendor")}) ||
		IsUnder(filepath.Join(d, "vendor-tools", "x"), []string{filepath.Join(d, "vendor")}) {
		t.Fatal("IsUnder boundary")
	}
}

// A root reached through a symlink (macOS /var -> /private/var, Windows 8.3
// names) must still contain a child that does not exist yet.
func TestIsUnderResolvesPrefixOfMissingPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "third_party"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not supported here")
	}
	root := filepath.Join(link, "third_party")
	if !IsUnder(filepath.Join(link, "third_party", "new", "file.js"), []string{root}) {
		t.Fatal("missing child under a symlinked root not recognised")
	}
	if !IsUnder(filepath.Join(real, "third_party", "x"), []string{root}) {
		t.Fatal("resolved path vs symlinked root")
	}
	if IsUnder(filepath.Join(link, "third_party-tools", "x"), []string{root}) {
		t.Fatal("not component-aware")
	}
}
