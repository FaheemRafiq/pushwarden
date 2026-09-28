package update

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/iocs"
	iocsdata "github.com/FaheemRafiq/threatscan/threatscan"
)

func withVersion(t *testing.T, v string) []byte {
	var m map[string]any
	if err := json.Unmarshal(iocsdata.Bundled, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = v
	b, _ := json.Marshal(m)
	return b
}

func TestUpdateIOCs(t *testing.T) {
	var body []byte
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()
	Version = "6.9.9"

	body = withVersion(t, "2099.01.01")
	ok, msg := updateIOCsFrom(dir, "2026.09.28", srv.URL)
	if !ok {
		t.Fatalf("newer file not installed: %s", msg)
	}
	if ua != "threatscan/6.9.9" {
		t.Errorf("User-Agent %q", ua)
	}
	if got, _ := os.ReadFile(iocs.UserPath(dir)); !bytes.Equal(got, body) {
		t.Error("installed file differs")
	}
	if i, err := iocs.Load(dir); err != nil || i.Version != "2099.01.01" {
		t.Errorf("Load after update: %v %v", i, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ioc-last-check")); err != nil {
		t.Error("ioc-last-check not written")
	}

	// same version: not installed
	if ok, _ := updateIOCsFrom(dir, "2099.01.01", srv.URL); ok {
		t.Error("same version installed")
	}
	// invalid data: rejected, existing file kept, stamp still written
	os.Remove(filepath.Join(dir, "ioc-last-check"))
	body = []byte(`{"version": "2100.01.01"}`)
	if ok, msg := updateIOCsFrom(dir, "2099.01.01", srv.URL); ok || msg == "" {
		t.Errorf("invalid file accepted: %s", msg)
	}
	if _, err := os.Stat(filepath.Join(dir, "ioc-last-check")); err != nil {
		t.Error("ioc-last-check not written after a rejected download")
	}
	// oversized: rejected
	body = bytes.Repeat([]byte(" "), maxIOCBytes+10)
	if ok, _ := updateIOCsFrom(dir, "2000.01.01", srv.URL); ok {
		t.Error("oversized file accepted")
	}
}
