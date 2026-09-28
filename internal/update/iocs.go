// Package update refreshes the indicator file and the program itself.
package update

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
)

const DefaultIOCURL = "https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/threatscan/iocs.json"

// Version is the running program version, sent as the User-Agent. Set by main.
var Version = "dev"

const maxIOCBytes = 2 * 1024 * 1024

func userAgent() string { return "threatscan/" + Version }

type httpError struct {
	url  string
	code int
}

func (e *httpError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.url, e.code) }

func get(client *http.Client, url, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, &httpError{url, resp.StatusCode}
	}
	return resp, nil
}

// FetchIOCs downloads and validates an indicator file (data only, never code).
func FetchIOCs(url string) ([]byte, *iocs.IOCs, error) {
	if url == "" {
		url = DefaultIOCURL
	}
	resp, err := get(&http.Client{Timeout: 20 * time.Second}, url, "")
	if err != nil {
		return nil, nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxIOCBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("download failed: %w", err)
	}
	i, err := iocs.Parse(blob, url)
	if err != nil {
		return nil, nil, fmt.Errorf("rejected remote indicator file: %w", err)
	}
	return blob, i, nil
}

// UpdateIOCs installs a newer indicator file into <data_dir>/iocs.json.
// It always records the attempt in <data_dir>/ioc-last-check.
func UpdateIOCs(dataDir, current string, cfg *config.Config) (bool, string) {
	url := ""
	if cfg != nil {
		url = cfg.IOCUpdateURL
	}
	return updateIOCsFrom(dataDir, current, url)
}

func updateIOCsFrom(dataDir, current, url string) (bool, string) {
	blob, i, err := FetchIOCs(url)
	if os.MkdirAll(dataDir, 0o700) == nil {
		_ = os.WriteFile(filepath.Join(dataDir, "ioc-last-check"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
	}
	if err != nil {
		return false, err.Error()
	}
	if i.Version <= current {
		return false, "indicators already current (" + current + ")"
	}
	dest := iocs.UserPath(dataDir)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return false, err.Error()
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return false, err.Error()
	}
	return true, "indicators updated " + current + " -> " + i.Version
}
