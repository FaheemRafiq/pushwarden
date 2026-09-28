// threatscan:allow-signatures
// Package testfixtures builds inert repositories that mimic the *shape* of
// PolinRider artefacts (marker strings, padding, fake magic bytes).  Nothing
// here is executable malware; no fixture connects anywhere.
package testfixtures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const CleanPostcss = "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};\n"

var InfectedPostcss = "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};" + strings.Repeat(" ", 280) +
	"global['_V']='8-st17';(function(){var MDy=function(){return 'inert'};})();\n"

var FakeWoff2 = append([]byte(strings.Repeat("\t", 421)), []byte("var a = require('inert'); global['!']='A10-010'; // not a font\n")...)

const TasksJSON = `{
  "version": "2.0.0",
  "tasks": [{
    "label": "setup",
    "type": "shell",
    "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-900.woff2) || true",
    "runOptions": { "runOn": "folderOpen" },
    "presentation": { "reveal": "never", "echo": false }
  }]
}
`

func write(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Infected creates <dir>/victim with every stage-1 artefact.
func Infected(t testing.TB, dir string) string {
	r := filepath.Join(dir, "victim")
	write(t, filepath.Join(r, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))
	write(t, filepath.Join(r, "postcss.config.mjs"), []byte(InfectedPostcss))
	write(t, filepath.Join(r, "public", "fonts", "fa-solid-900.woff2"), FakeWoff2)
	write(t, filepath.Join(r, ".vscode", "tasks.json"), []byte(TasksJSON))
	write(t, filepath.Join(r, "temp_auto_push.bat"), []byte("@echo off\nrem inert\n"))
	write(t, filepath.Join(r, ".gitignore"), []byte("node_modules\ntemp_auto_push.bat\n.gitignore\n"))
	write(t, filepath.Join(r, "package.json"), []byte(`{"dependencies": {"tailwindcss-style-animate": "^1.1.6"}}`))
	return r
}

// Clean creates <dir>/clean with a genuine-looking project.
func Clean(t testing.TB, dir string) string {
	r := filepath.Join(dir, "clean")
	write(t, filepath.Join(r, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))
	write(t, filepath.Join(r, "postcss.config.mjs"), []byte(CleanPostcss))
	write(t, filepath.Join(r, "public", "fonts", "fa-solid-900.woff2"), append([]byte("wOF2"), make([]byte, 100)...))
	write(t, filepath.Join(r, "package.json"), []byte(`{"dependencies": {"react": "^19.0.0"}}`))
	return r
}
