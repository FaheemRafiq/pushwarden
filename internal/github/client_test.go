package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListReposPaginatesAndFiltersPush(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/user":
			json.NewEncoder(w).Encode(map[string]string{"login": "me"})
		case r.URL.Path == "/user/repos" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/user/repos?page=2>; rel="next"`, srv.URL))
			fmt.Fprint(w, `[{"full_name":"me/a","name":"a","default_branch":"main","clone_url":"u","owner":{"login":"me"},"permissions":{"push":true}},
			               {"full_name":"other/ro","name":"ro","owner":{"login":"other"},"permissions":{"push":false}}]`)
		case r.URL.Path == "/user/repos":
			fmt.Fprint(w, `[{"full_name":"org/b","name":"b","fork":true,"archived":true,"owner":{"login":"org"},"permissions":{"admin":true}}]`)
		case r.URL.Path == "/repos/me/a":
			fmt.Fprint(w, `{"full_name":"me/a","name":"a","owner":{"login":"me"},"permissions":{"push":true}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := New("tok", srv.URL)
	if v, err := c.Viewer(context.Background()); err != nil || v != "me" {
		t.Fatal(v, err)
	}
	repos, err := c.ListRepos(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].FullName != "me/a" || repos[1].FullName != "org/b" || !repos[1].Fork || !repos[1].Archived {
		t.Fatalf("%+v", repos)
	}
	if _, err := c.GetRepo(context.Background(), "me/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRepo(context.Background(), "nope"); err == nil {
		t.Fatal("expected owner/name error")
	}
	if _, err := New("bad", srv.URL).Viewer(context.Background()); err == nil {
		t.Fatal("expected 401")
	}
}

func TestRateLimitWaitsOnce(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(2*time.Second).Unix()))
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"login": "me"})
	}))
	defer srv.Close()
	c := New("tok", srv.URL)
	slept := time.Duration(0)
	c.Sleep = func(d time.Duration) { slept = d }
	if _, err := c.Viewer(context.Background()); err != nil || calls != 2 || slept <= 0 {
		t.Fatal(err, calls, slept)
	}
}
