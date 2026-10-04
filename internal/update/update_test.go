package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// fakeBins builds testdata/fakebin as v0.1.0 (installed), v0.2.0 (good) and
// v0.2.0-that-crashes (broken).
func fakeBins(t *testing.T) (old, good, broken string) {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "ts-fakebin")
		if buildErr != nil {
			return
		}
		goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
		for _, b := range []struct{ name, ldflags string }{
			{"old", "-X main.version=0.1.0"},
			{"good", "-X main.version=0.2.0"},
			{"broken", "-X main.version=0.2.0 -X main.broken=1"},
		} {
			// -buildvcs=false: CI containers run as root over a checkout owned by
			// another user, and git then refuses to report the VCS status.
			out, err := exec.Command(goBin, "build", "-buildvcs=false", "-o", filepath.Join(binDir, b.name+exeSuffix()),
				"-ldflags", b.ldflags, "./testdata/fakebin").CombinedOutput()
			if err != nil {
				buildErr = fmt.Errorf("build %s: %v\n%s", b.name, err, out)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(binDir, "old"+exeSuffix()), filepath.Join(binDir, "good"+exeSuffix()), filepath.Join(binDir, "broken"+exeSuffix())
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	t      *testing.T
	srv    *httptest.Server
	files  map[string][]byte
	rels   []Release
	pub    string
	priv   ed25519.PrivateKey
	u      *Updater
	oldBin []byte
}

// newFixture serves a release v0.2.0 whose binary is `bin`, signed with a test key.
func newFixture(t *testing.T, bin string) *fixture {
	old, _, _ := fakeBins(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, files: map[string][]byte{}, pub: base64.StdEncoding.EncodeToString(pub), priv: priv}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases" {
			json.NewEncoder(w).Encode(f.rels)
			return
		}
		if r.URL.Path == "/releases/latest" {
			for _, rel := range f.rels {
				if !rel.Draft && !rel.Prerelease {
					json.NewEncoder(w).Encode(rel)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b))) // as a real download server does
		w.Write(b)
	}))
	t.Cleanup(f.srv.Close)

	dir := t.TempDir()
	exe := filepath.Join(dir, "pushwarden"+exeSuffix())
	f.oldBin = read(t, old)
	os.WriteFile(exe, f.oldBin, 0o755)
	f.u = &Updater{DataDir: t.TempDir(), Current: "0.1.0", Exe: exe, APIURL: f.srv.URL + "/releases/latest",
		Channel: "stable", Keys: []string{f.pub}, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Client: f.srv.Client()}
	f.publish("v0.2.0", read(t, bin))
	return f
}

// publish (re)defines the single stable release with a correctly signed checksum file.
func (f *fixture) publish(tag string, bin []byte) {
	name := f.u.AssetName()
	sum := sha256.Sum256(bin)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n" + strings.Repeat("0", 64) + "  other-asset\n")
	f.files[name] = bin
	f.files["checksums.txt"] = sums
	f.files["checksums.txt.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, sums)) + "\n")
	var assets []Asset
	for _, n := range []string{name, "checksums.txt", "checksums.txt.sig"} {
		assets = append(assets, Asset{Name: n, URL: f.srv.URL + "/dl/" + n})
	}
	f.rels = []Release{{Tag: tag, Assets: assets}}
}

func (f *fixture) installed() []byte { return read(f.t, f.u.Exe) }

func (f *fixture) mustRefuse(want string) {
	f.t.Helper()
	rel, err := f.u.Check()
	if err != nil || rel == nil {
		f.t.Fatalf("Check: rel=%v err=%v", rel, err)
	}
	err = f.u.Apply(rel)
	if err == nil || !strings.Contains(err.Error(), want) {
		f.t.Fatalf("Apply error = %v, want it to mention %q", err, want)
	}
	if !bytes.Equal(f.installed(), f.oldBin) {
		f.t.Fatal("installed binary changed after a refused update")
	}
	if _, err := os.Stat(f.u.workDir()); err == nil {
		f.t.Fatal("downloads were not deleted")
	}
	if _, err := os.Stat(f.u.Exe + ".old"); err == nil {
		f.t.Fatal(".old left behind by a refused update")
	}
}

func TestValidUpdateInstalled(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	rel, err := f.u.Check()
	if err != nil || rel == nil || rel.Version() != "0.2.0" {
		t.Fatalf("Check: %+v %v", rel, err)
	}
	if err := f.u.Apply(rel); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.installed(), read(t, good)) {
		t.Fatal("new binary not installed")
	}
	if !bytes.Equal(read(t, f.u.Exe+".old"), f.oldBin) {
		t.Fatal(".old is not the previous binary")
	}
	st := f.u.LoadState()
	if st.Version != "0.2.0" || st.Previous != "0.1.0" || st.Time == 0 || st.Confirmed {
		t.Fatalf("state: %+v", st)
	}
	// the new version starts, writes a heartbeat, and is confirmed
	nu := *f.u
	nu.Current = "0.2.0"
	if rb, err := nu.OnGuardStart("0.1.0", time.Now().Add(-time.Hour)); rb || err != nil {
		t.Fatalf("first start rolled back: %v %v", rb, err)
	}
	if v := nu.Confirm("0.2.0"); v != "0.2.0" {
		t.Fatalf("Confirm = %q", v)
	}
	if _, err := os.Stat(f.u.Exe + ".old"); err == nil {
		t.Fatal(".old not deleted after confirmation")
	}
	if nu.Confirm("0.2.0") != "" {
		t.Fatal("confirmed twice")
	}
	// nothing newer now
	if rel, _ := nu.Check(); rel != nil {
		t.Fatalf("offered %s again", rel.Tag)
	}
}

func TestTamperedChecksumRefused(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	f.files["checksums.txt"] = append([]byte("# edited after signing\n"), f.files["checksums.txt"]...)
	f.mustRefuse("signature")
}

func TestTamperedBinaryRefused(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	f.files[f.u.AssetName()] = append(read(t, good), 0)
	f.mustRefuse("SHA-256 mismatch")
}

func TestWrongKeyAndNoKeyRefused(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	f.u.Keys = []string{base64.StdEncoding.EncodeToString(other)}
	f.mustRefuse("does not match")
	f.u.Keys = nil
	f.mustRefuse("no signing key")
}

func TestBrokenBinaryRefused(t *testing.T) {
	_, _, broken := fakeBins(t)
	f := newFixture(t, broken)
	f.mustRefuse("self-test")
}

func TestMissingHeartbeatRollsBack(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	rel, _ := f.u.Check()
	if err := f.u.Apply(rel); err != nil {
		t.Fatal(err)
	}
	nu := *f.u
	nu.Current = "0.2.0"
	// first start of 0.2.0: counted, no rollback yet
	if rb, _ := nu.OnGuardStart("0.1.0", time.Now().Add(-time.Hour)); rb {
		t.Fatal("rolled back on the first start")
	}
	// it crashed before writing a heartbeat; the service manager restarts it
	rb, err := nu.OnGuardStart("0.1.0", time.Now().Add(-time.Hour))
	if err != nil || !rb {
		t.Fatalf("no rollback: %v %v", rb, err)
	}
	if !bytes.Equal(f.installed(), f.oldBin) {
		t.Fatal("previous binary not restored")
	}
	st := f.u.LoadState()
	if len(st.Failed) != 1 || st.Failed[0] != "0.2.0" || st.pending() {
		t.Fatalf("state after rollback: %+v", st)
	}
	// the failed version is never offered again
	if rel, _ := f.u.Check(); rel != nil {
		t.Fatalf("failed version offered again: %s", rel.Tag)
	}
	// the restored old binary's own start is not treated as an update
	if rb, _ := f.u.OnGuardStart("", time.Time{}); rb {
		t.Fatal("old binary rolled back")
	}
}

func TestHealthyRestartDoesNotRollBack(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	rel, _ := f.u.Check()
	f.u.Apply(rel)
	nu := *f.u
	nu.Current = "0.2.0"
	nu.OnGuardStart("", time.Time{})
	// the first run wrote a heartbeat as 0.2.0, then was restarted (e.g. logout)
	if rb, _ := nu.OnGuardStart("0.2.0", time.Now()); rb {
		t.Fatal("healthy version rolled back")
	}
}

func TestChannelsAndDrafts(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	a := f.rels[0].Assets
	f.rels = []Release{
		{Tag: "v6.0.0", Assets: a}, // withdrawn: never offered, although its number is highest
		{Tag: "v1.0.0", Draft: true, Assets: a},
		{Tag: "v0.4.0-rc1", Prerelease: true, Assets: a},
		{Tag: "v0.3.0", Assets: a},
		{Tag: "v0.0.9", Assets: a},
	}
	f.u.APIURL = f.srv.URL + "/releases"
	if rel, _ := f.u.Check(); rel == nil || rel.Tag != "v0.3.0" {
		t.Fatalf("stable picked %+v", rel)
	}
	f.u.Channel = "beta"
	if rel, _ := f.u.Check(); rel == nil || rel.Tag != "v0.4.0-rc1" {
		t.Fatalf("beta picked %+v", rel)
	}
	f.rels = nil
	f.u.APIURL = f.srv.URL + "/releases/latest" // 404: no release published yet
	if rel, err := f.u.Check(); rel != nil || err != nil {
		t.Fatalf("no releases: %+v %v", rel, err)
	}
	f.u.APIURL = f.srv.URL + "/releases"
	f.rels = []Release{{Tag: "v1.0.0", Assets: a}}
	f.u.Current = "1.0.0"
	if rel, _ := f.u.Check(); rel != nil {
		t.Fatalf("offered a downgrade: %s", rel.Tag)
	}
}

func TestCompareVersions(t *testing.T) {
	for v, want := range map[string]bool{"v6.0.0": true, "6.0.0": true, "6.0.0-rc1": true, "6.0.0-dev": true,
		"6.0.0+build.1": true, "0.1.0": false, "6.0.1": false, "16.0.0": false, "0.6.0": false} {
		if IsWithdrawn(v) != want {
			t.Errorf("IsWithdrawn(%q) = %v, want %v", v, !want, want)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.0.0", "v6.0.0", 0}, {"6.0.1", "6.0.0", 1}, {"6.10.0", "6.9.9", 1}, {"5.2.0", "6.0.0", -1},
		{"6.0.0-rc1", "6.0.0", -1}, {"6.0.0-rc.2", "6.0.0-rc.10", -1}, {"6.0.0-dev", "6.0.0", -1}, {"6.0.0", "6.0.0-rc1", 1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The program download reports its progress; the small checksum files do not.
func TestDownloadProgress(t *testing.T) {
	_, good, _ := fakeBins(t)
	f := newFixture(t, good)
	size := int64(len(read(t, good)))
	var calls int
	var last, total int64
	f.u.Progress = func(done, all int64) {
		if all != size || done < last || done > all {
			t.Errorf("progress %d/%d (binary is %d bytes, last was %d)", done, all, size, last)
		}
		calls, last, total = calls+1, done, all
	}
	rel, err := f.u.Check()
	if err != nil || rel == nil {
		t.Fatal(rel, err)
	}
	if err := f.u.Apply(rel); err != nil {
		t.Fatal(err)
	}
	if calls == 0 || last != total || total != size {
		t.Fatalf("the download must end at 100%%: calls=%d last=%d total=%d size=%d", calls, last, total, size)
	}
}
