package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/config"
)

const (
	DefaultAPIURL  = "https://api.github.com/repos/FaheemRafiq/pushwarden/releases/latest"
	defaultListURL = "https://api.github.com/repos/FaheemRafiq/pushwarden/releases"
	maxBinaryBytes = 200 << 20
	// RollbackWindow: a restart this soon after an update, without a heartbeat
	// from the new version, means the new version crashed.
	RollbackWindow = 2 * time.Minute
)

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

func (r *Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

func (r *Release) asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// State is <data_dir>/update-state.json.
type State struct {
	Version   string   `json:"version,omitempty"`  // installed by the last update
	Previous  string   `json:"previous,omitempty"` // what it replaced
	Time      int64    `json:"time,omitempty"`     // Unix seconds
	Starts    int      `json:"starts,omitempty"`   // guard starts on Version since the update
	Confirmed bool     `json:"confirmed,omitempty"`
	Failed    []string `json:"failed,omitempty"` // versions rolled back; never retried
}

func (s *State) failed(v string) bool {
	for _, f := range s.Failed {
		if f == v {
			return true
		}
	}
	return false
}

func (s *State) pending() bool { return s.Version != "" && !s.Confirmed }

type Updater struct {
	DataDir string
	Current string // running version
	Exe     string // binary to replace
	APIURL  string // releases API (latest object, or a list)
	Channel string // stable | beta
	Keys    []string
	GOOS    string
	GOARCH  string
	Client  *http.Client
	Log     func(string)
}

func New(dataDir, exe string, cfg *config.Config) *Updater {
	u := &Updater{DataDir: dataDir, Current: Version, Exe: exe, Keys: PublicKeys,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Client: &http.Client{Timeout: 10 * time.Minute}}
	if cfg != nil {
		u.APIURL, u.Channel = cfg.UpdateAPIURL, cfg.UpdateChannel
	}
	return u
}

func (u *Updater) log(m string) {
	if u.Log != nil {
		u.Log(m)
	}
}

func (u *Updater) statePath() string { return filepath.Join(u.DataDir, "update-state.json") }

func (u *Updater) LoadState() *State {
	s := &State{}
	if b, err := os.ReadFile(u.statePath()); err == nil {
		_ = json.Unmarshal(b, s)
	}
	return s
}

func (u *Updater) saveState(s *State) error {
	if err := os.MkdirAll(u.DataDir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := u.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.statePath())
}

// AssetName is the release asset for this OS/arch.
func (u *Updater) AssetName() string {
	n := "pushwarden-" + u.GOOS + "-" + u.GOARCH
	if u.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// ── 1. find a newer release ─────────────────────────────────────────────────

func (u *Updater) apiURL() string {
	switch {
	case u.APIURL != "":
		return u.APIURL
	case u.Channel == "beta":
		return defaultListURL
	}
	return DefaultAPIURL
}

// Check returns the newest release newer than Current, or nil.
func (u *Updater) Check() (*Release, error) {
	resp, err := get(u.Client, u.apiURL(), "application/vnd.github+json")
	var he *httpError
	if errors.As(err, &he) && he.code == http.StatusNotFound {
		return nil, nil // GitHub's answer to releases/latest before the first release
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var rels []Release
	if err := json.Unmarshal(body, &rels); err != nil {
		var one Release
		if err := json.Unmarshal(body, &one); err != nil {
			return nil, fmt.Errorf("releases API: %w", err)
		}
		rels = []Release{one}
	}
	st := u.LoadState()
	var best *Release
	for i := range rels {
		r := &rels[i]
		if r.Draft || r.Tag == "" || (r.Prerelease && u.Channel != "beta") || st.failed(r.Version()) || IsWithdrawn(r.Version()) {
			continue
		}
		if CompareVersions(r.Version(), u.Current) <= 0 {
			continue
		}
		if best == nil || CompareVersions(r.Version(), best.Version()) > 0 {
			best = r
		}
	}
	return best, nil
}

// ── 2-5. download, verify, test, swap ───────────────────────────────────────

func (u *Updater) download(url, dst string, limit int64) error {
	resp, err := get(u.Client, url, "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("%s is larger than %d bytes", filepath.Base(dst), limit)
	}
	return err
}

// VerifySignature checks sig (base64 or raw ed25519) over msg against any key.
func VerifySignature(msg, sig []byte, keys []string) error {
	if len(keys) == 0 {
		return errors.New("no signing key is built into this version; refusing to update")
	}
	raw := sig
	if len(raw) != ed25519.SignatureSize {
		d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil || len(d) != ed25519.SignatureSize {
			return errors.New("checksums.txt.sig is not an ed25519 signature")
		}
		raw = d
	}
	for _, k := range keys {
		pk, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pk), msg, raw) {
			return nil
		}
	}
	return errors.New("checksums.txt signature does not match any trusted key")
}

// ChecksumFor finds name in a sha256sum-style file.
func ChecksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (u *Updater) workDir() string { return filepath.Join(filepath.Dir(u.Exe), "update") }

// Apply installs rel over Exe. On any failure the downloads are deleted and
// the current binary is left untouched.
func (u *Updater) Apply(rel *Release) (err error) {
	if CompareVersions(rel.Version(), u.Current) <= 0 {
		return fmt.Errorf("%s is not newer than %s", rel.Version(), u.Current)
	}
	name := u.AssetName()
	bin, sums, sig := rel.asset(name), rel.asset("checksums.txt"), rel.asset("checksums.txt.sig")
	if bin == nil || sums == nil || sig == nil {
		return fmt.Errorf("release %s lacks %s, checksums.txt or checksums.txt.sig", rel.Tag, name)
	}
	dir := u.workDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	newBin := filepath.Join(dir, name)
	for _, d := range []struct {
		url, dst string
		max      int64
	}{{sums.URL, filepath.Join(dir, "checksums.txt"), 1 << 20},
		{sig.URL, filepath.Join(dir, "checksums.txt.sig"), 4096},
		{bin.URL, newBin, maxBinaryBytes}} {
		if err := u.download(d.url, d.dst, d.max); err != nil {
			return fmt.Errorf("download: %w", err)
		}
	}
	sumsB, _ := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	sigB, _ := os.ReadFile(filepath.Join(dir, "checksums.txt.sig"))
	if err := VerifySignature(sumsB, sigB, u.Keys); err != nil {
		return err
	}
	want, err := ChecksumFor(sumsB, name)
	if err != nil {
		return err
	}
	if got, err := fileSHA256(newBin); err != nil || got != want {
		return fmt.Errorf("%s SHA-256 mismatch (got %s, want %s)", name, got, want)
	}
	if err := os.Chmod(newBin, 0o755); err != nil {
		return err
	}
	// 4. the new binary must run and report the version it claims to be
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, newBin, "version").CombinedOutput()
	if runErr != nil || !strings.Contains(string(out), rel.Version()) {
		return fmt.Errorf("new binary failed its self-test (%v): %s", runErr, strings.TrimSpace(string(out)))
	}
	// 5. rename-old then rename-new: Windows lets a running exe be renamed, not deleted
	old := u.Exe + ".old"
	os.Remove(old)
	if err := os.Rename(u.Exe, old); err != nil {
		return fmt.Errorf("move current binary aside: %w", err)
	}
	if err := os.Rename(newBin, u.Exe); err != nil {
		_ = os.Rename(old, u.Exe)
		return fmt.Errorf("install new binary: %w", err)
	}
	os.RemoveAll(dir)
	st := u.LoadState()
	st.Version, st.Previous, st.Time, st.Starts, st.Confirmed = rel.Version(), u.Current, time.Now().Unix(), 0, false
	if err := u.saveState(st); err != nil {
		u.log("update: could not record state: " + err.Error())
	}
	u.log("update: installed " + rel.Version() + " (was " + u.Current + ")")
	return nil
}

// ── 6-7. rollback and confirmation ──────────────────────────────────────────

// OnGuardStart is called before the guard's first pass. It counts starts of a
// freshly updated version; if the previous start of that version never wrote
// a heartbeat, it restores the .old binary and returns true (caller restarts).
// hbVersion/hbTime describe the last heartbeat (empty/zero if none).
func (u *Updater) OnGuardStart(hbVersion string, hbTime time.Time) (bool, error) {
	st := u.LoadState()
	if !st.pending() || st.Version != u.Current {
		return false, nil
	}
	updated := time.Unix(st.Time, 0)
	healthy := hbVersion == st.Version && !hbTime.Before(updated)
	if st.Starts >= 1 && !healthy && time.Since(updated) < RollbackWindow {
		old := u.Exe + ".old"
		if _, err := os.Stat(old); err != nil {
			return false, nil
		}
		bad := u.Exe + ".failed"
		os.Remove(bad)
		if err := os.Rename(u.Exe, bad); err != nil {
			return false, err
		}
		if err := os.Rename(old, u.Exe); err != nil {
			_ = os.Rename(bad, u.Exe)
			return false, err
		}
		os.Remove(bad) // fails on Windows while running; harmless
		st.Failed = append(st.Failed, st.Version)
		u.log("update: " + st.Version + " did not start cleanly; rolled back to " + st.Previous)
		st.Version, st.Starts, st.Confirmed = "", 0, false
		return true, u.saveState(st)
	}
	st.Starts++
	return false, u.saveState(st)
}

// Confirm runs once the new version has written a heartbeat: it deletes the
// .old binary and returns the version to announce ("" if nothing to do).
func (u *Updater) Confirm(hbVersion string) string {
	st := u.LoadState()
	if !st.pending() || st.Version != u.Current || hbVersion != u.Current {
		return ""
	}
	st.Confirmed = true
	if err := u.saveState(st); err != nil {
		return ""
	}
	os.Remove(u.Exe + ".old")
	os.Remove(u.Exe + ".failed")
	return st.Version
}
