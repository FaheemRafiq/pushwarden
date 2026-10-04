// Package github is the small slice of the GitHub REST API that
// `pushwarden github-clean` needs: who am I, which repositories can I push to.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultAPI = "https://api.github.com"

// Repo is one repository the token can see.
type Repo struct {
	FullName      string `json:"full_name"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	Push          bool   `json:"push"`
}

type Client struct {
	Token string
	API   string
	HTTP  *http.Client
	// Sleep is swapped out by tests; it waits for the rate limit to reset.
	Sleep func(time.Duration)
}

func New(token, api string) *Client {
	if api == "" {
		api = DefaultAPI
	}
	return &Client{Token: token, API: strings.TrimRight(api, "/"), HTTP: &http.Client{Timeout: 60 * time.Second}, Sleep: time.Sleep}
}

type apiRepo struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	Permissions struct {
		Push  bool `json:"push"`
		Admin bool `json:"admin"`
	} `json:"permissions"`
}

func (a apiRepo) repo() Repo {
	return Repo{FullName: a.FullName, Owner: a.Owner.Login, Name: a.Name, DefaultBranch: a.DefaultBranch,
		CloneURL: a.CloneURL, HTMLURL: a.HTMLURL, Private: a.Private, Fork: a.Fork, Archived: a.Archived,
		Push: a.Permissions.Push || a.Permissions.Admin}
}

// get performs one GET, retrying once after a primary rate-limit reset, and
// returns the body plus the `next` page link (empty when there is none).
func (c *Client) get(ctx context.Context, u string, out any) (next string, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "pushwarden")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if out != nil {
				if err := json.Unmarshal(body, out); err != nil {
					return "", fmt.Errorf("GitHub returned unexpected JSON for %s: %v", u, err)
				}
			}
			return nextLink(resp.Header.Get("Link")), nil
		case resp.StatusCode == http.StatusUnauthorized:
			return "", errors.New("GitHub rejected the token (401). Check that it is valid and not expired")
		case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
			resp.Header.Get("X-RateLimit-Remaining") == "0" && attempt == 0:
			reset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
			wait := time.Until(time.Unix(reset, 0)) + time.Second
			if wait < time.Second || wait > 15*time.Minute {
				return "", fmt.Errorf("GitHub API rate limit exhausted; try again after %s", time.Unix(reset, 0).Format(time.Kitchen))
			}
			c.Sleep(wait)
			continue
		case resp.StatusCode == http.StatusNotFound:
			return "", fmt.Errorf("not found (404): %s. The token may lack access to it", u)
		}
		return "", fmt.Errorf("GitHub API %s: HTTP %d: %s", u, resp.StatusCode, trunc(string(body), 200))
	}
	return "", errors.New("GitHub API: gave up after rate-limit wait")
}

var linkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(h string) string {
	if m := linkRe.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Viewer returns the login of the token's user.
func (c *Client) Viewer(ctx context.Context) (string, error) {
	var v struct {
		Login string `json:"login"`
	}
	if _, err := c.get(ctx, c.API+"/user", &v); err != nil {
		return "", err
	}
	return v.Login, nil
}

// ListRepos returns every repository the token can push to: own repos,
// collaborations and organisation repos. Archived repos and forks are included
// and flagged; the caller filters.
func (c *Client) ListRepos(ctx context.Context) ([]Repo, error) {
	u := c.API + "/user/repos?" + url.Values{
		"per_page":    {"100"},
		"affiliation": {"owner,collaborator,organization_member"},
		"sort":        {"full_name"},
		"direction":   {"asc"},
	}.Encode()
	var out []Repo
	seen := map[string]bool{}
	for u != "" {
		var page []apiRepo
		next, err := c.get(ctx, u, &page)
		if err != nil {
			return nil, err
		}
		for _, a := range page {
			r := a.repo()
			if r.Push && !seen[r.FullName] {
				seen[r.FullName] = true
				out = append(out, r)
			}
		}
		u = next
	}
	return out, nil
}

// GetRepo fetches one repository by "owner/name".
func (c *Client) GetRepo(ctx context.Context, fullName string) (Repo, error) {
	owner, name, ok := strings.Cut(fullName, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return Repo{}, fmt.Errorf("repository must be owner/name, got %q", fullName)
	}
	var a apiRepo
	if _, err := c.get(ctx, c.API+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), &a); err != nil {
		return Repo{}, err
	}
	return a.repo(), nil
}
