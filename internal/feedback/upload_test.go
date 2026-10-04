package feedback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/journal"
)

// table is a stand-in for the central table: it stores rows by event_id and
// can be told to fail, or to refuse duplicates the way a table without the
// skip rule does.
type table struct {
	mu        sync.Mutex
	rows      map[string]map[string]any
	bodies    []string
	headers   []http.Header
	batches   []int
	fail      int  // answer this many requests with 500 before working
	loseReply bool // store the batch, then answer 500 once
	strict    bool // 409 for a batch containing a stored event_id
}

func (tb *table) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	tb.bodies = append(tb.bodies, string(b))
	tb.headers = append(tb.headers, r.Header.Clone())
	if tb.fail > 0 {
		tb.fail--
		http.Error(w, `{"message":"down"}`, 500)
		return
	}
	var in []map[string]any
	if err := json.Unmarshal(b, &in); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	tb.batches = append(tb.batches, len(in))
	if tb.strict {
		for _, row := range in {
			if _, dup := tb.rows[row["event_id"].(string)]; dup {
				http.Error(w, `{"code":"23505"}`, 409)
				return
			}
		}
	}
	for _, row := range in {
		id := row["event_id"].(string)
		if _, dup := tb.rows[id]; !dup {
			tb.rows[id] = row
		}
	}
	if tb.loseReply {
		tb.loseReply = false
		http.Error(w, "gateway timeout", 504)
		return
	}
	w.WriteHeader(201)
}

func newTable(t *testing.T) (*table, *httptest.Server) {
	tb := &table{rows: map[string]map[string]any{}}
	srv := httptest.NewServer(tb)
	t.Cleanup(srv.Close)
	return tb, srv
}

// journalWith writes n events, several per second, and returns the data dir.
func journalWith(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	j := journal.Open(dir, "0.4.0", "2026.10.01.1")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < n; i++ {
		// seven events share each timestamp, and some are identical in every field
		j.Write(journal.Event{TS: base.Add(time.Duration(i/7) * time.Second).Format(time.RFC3339), Kind: journal.KindFinding, Sev: "WARNING",
			Category: "history_payload", Title: "3 commits", Key: "k", Note: fmt.Sprint(i)})
	}
	return dir
}

func notes(tb *table) map[string]bool {
	out := map[string]bool{}
	for _, r := range tb.rows {
		out[r["note"].(string)] = true
	}
	return out
}

func states(evs []journal.Event) string {
	var b strings.Builder
	for _, e := range evs {
		switch {
		case e.Uploaded == nil:
			b.WriteByte('?')
		case *e.Uploaded:
			b.WriteByte('U')
		default:
			b.WriteByte('w')
		}
	}
	return b.String()
}

func TestUploadBatchesHeadersAndPerEventFlag(t *testing.T) {
	tb, srv := newTable(t)
	dir := journalWith(t, 450)
	up := &Uploader{DataDir: dir, URL: srv.URL + "/rest/v1/pushwarden_events", Key: "anon-key", MachineID: "m1", OS: "linux"}
	if rows, total := up.Pending(5); len(rows) != 5 || total != 450 {
		t.Fatalf("pending: %d of %d", len(rows), total)
	}
	if st := up.Status(); st.Uploaded != 0 || st.Waiting != 450 || !st.LastSuccess.IsZero() {
		t.Fatalf("status before: %+v", st)
	}
	if len(tb.bodies) != 0 {
		t.Fatal("Pending and Status must not send anything")
	}
	if _, err := os.Stat(up.statePath()); err == nil {
		t.Fatal("Pending and Status must not write the state")
	}
	r := up.Run()
	if r.Err != nil || r.Sent != 450 || r.Waiting != 0 {
		t.Fatalf("%+v", r)
	}
	if fmt.Sprint(tb.batches) != "[200 200 50]" {
		t.Fatalf("batches: %v", tb.batches)
	}
	if len(tb.rows) != 450 || len(notes(tb)) != 450 {
		t.Fatalf("stored %d rows, %d distinct events: same-second events were merged or lost", len(tb.rows), len(notes(tb)))
	}
	h := tb.headers[0]
	if h.Get("apikey") != "anon-key" || h.Get("Authorization") != "Bearer anon-key" || h.Get("Prefer") != "return=minimal" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", h)
	}
	if st := up.Status(); st.Uploaded != 450 || st.Waiting != 0 || st.LastSuccess.IsZero() || st.Failures != 0 {
		t.Fatalf("status after: %+v", st)
	}
	// nothing new: not due, and a run sends no request
	n := len(tb.bodies)
	if up.Due(time.Now().Add(24 * time.Hour)) {
		t.Fatal("nothing new in the journal: no upload is due")
	}
	if r := up.Run(); r.Sent != 0 || r.Waiting != 0 || r.Err != nil || len(tb.bodies) != n {
		t.Fatalf("idle run %+v requests=%d", r, len(tb.bodies)-n)
	}
	// new events, one stamped a day in the past (clock set back): position decides, not time
	j := journal.Open(dir, "0.4.0", "x")
	j.Write(journal.Event{TS: time.Now().Add(-24 * time.Hour).Format(time.RFC3339), Kind: journal.KindAction, Action: "kill", Note: "older-timestamp"})
	j.Write(journal.Event{Kind: journal.KindGuard, Title: "guard started", Note: "new"})
	evs := journal.Read(dir, journal.Filter{Archives: true})
	up.Mark(evs)
	if got := states(evs); got != strings.Repeat("U", 450)+"ww" {
		t.Fatalf("flags before the second run: …%s", got[440:])
	}
	if up.Due(time.Now()) {
		t.Fatal("a successful upload a moment ago: the next is due in 10 minutes")
	}
	if !up.Due(time.Now().Add(11 * time.Minute)) {
		t.Fatal("new events and 10 minutes passed: an upload is due")
	}
	if r := up.Run(); r.Sent != 2 || r.Err != nil {
		t.Fatalf("after new events: %+v", r)
	}
	if len(tb.rows) != 452 || !notes(tb)["older-timestamp"] || !notes(tb)["new"] {
		t.Fatalf("rows=%d", len(tb.rows))
	}
	evs = journal.Read(dir, journal.Filter{Kinds: []string{journal.KindAction, journal.KindGuard}})
	up.Mark(evs)
	if got := states(evs); got != "UU" {
		t.Fatalf("flags on a filtered read: %s", got)
	}
}

func TestOfflineThenOnline(t *testing.T) {
	for _, strict := range []bool{false, true} {
		tb, srv := newTable(t)
		tb.strict = strict
		dir := journalWith(t, 450)
		up := &Uploader{DataDir: dir, URL: srv.URL, Key: "k", MachineID: "m1", OS: "linux"}
		now := time.Now()
		if !up.Due(now) {
			t.Fatal("events waiting and no attempt yet: due")
		}
		// offline: every run fails, nothing is flagged as uploaded, the retry delay grows 1, 2, 4, 8, 10, 10
		for i, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute} {
			tb.fail = 1
			r := up.Run()
			if r.Err == nil || r.Sent != 0 || r.Waiting != 450 || r.Failures != i+1 || r.Recovered {
				t.Fatalf("strict=%v failure %d: %+v", strict, i+1, r)
			}
			if up.Due(now.Add(wait-10*time.Second)) || !up.Due(now.Add(wait+10*time.Second)) {
				t.Fatalf("after %d failures the retry should come after %v", i+1, wait)
			}
		}
		st := up.Status()
		if st.Uploaded != 0 || st.Waiting != 450 || st.Failures != 6 || st.LastError == "" || st.FailingSince.IsZero() {
			t.Fatalf("offline status: %+v", st)
		}
		evs := journal.Read(dir, journal.Filter{})
		up.Mark(evs)
		if states(evs) != strings.Repeat("w", 450) {
			t.Fatal("events were flagged uploaded while the server was down")
		}
		// the first batch is stored but its answer is lost: those 200 stay "waiting" and go again
		tb.loseReply = true
		if r := up.Run(); r.Err == nil || r.Sent != 0 || len(tb.rows) != 200 {
			t.Fatalf("strict=%v lost reply: %+v rows=%d", strict, r, len(tb.rows))
		}
		// back online
		r := up.Run()
		if r.Err != nil || r.Sent != 450 || r.Waiting != 0 || !r.Recovered {
			t.Fatalf("strict=%v recovery: %+v", strict, r)
		}
		if len(tb.rows) != 450 || len(notes(tb)) != 450 {
			t.Fatalf("strict=%v: %d rows, %d distinct after recovery", strict, len(tb.rows), len(notes(tb)))
		}
		if st := up.Status(); st.Uploaded != 450 || st.Failures != 0 || st.LastError != "" || !st.FailingSince.IsZero() {
			t.Fatalf("status after recovery: %+v", st)
		}
		// a lost state file resends everything; the table ends up unchanged
		os.Remove(up.statePath())
		if r := up.Run(); r.Err != nil || r.Sent != 450 || len(tb.rows) != 450 {
			t.Fatalf("strict=%v: after state loss %+v rows=%d", strict, r, len(tb.rows))
		}
	}
}

func TestUploadFollowsTheConfiguredURL(t *testing.T) {
	tb1, srv1 := newTable(t)
	tb2, srv2 := newTable(t)
	dir := journalWith(t, 30)
	up := &Uploader{DataDir: dir, URL: srv1.URL, MachineID: "m1"}
	if r := up.Run(); r.Sent != 30 || r.Err != nil {
		t.Fatalf("%+v", r)
	}
	// another destination has received nothing: every event is waiting again, for that URL
	up.URL = srv2.URL
	evs := journal.Read(dir, journal.Filter{})
	up.Mark(evs)
	if st := up.Status(); st.Uploaded != 0 || st.Waiting != 30 || states(evs) != strings.Repeat("w", 30) || !up.Due(time.Now()) {
		t.Fatalf("after a URL change: %+v %s", st, states(evs))
	}
	if r := up.Run(); r.Sent != 30 || r.Err != nil || len(tb2.rows) != 30 || len(tb1.rows) != 30 {
		t.Fatalf("%+v first=%d second=%d", r, len(tb1.rows), len(tb2.rows))
	}
}

func TestUploadAcrossRotation(t *testing.T) {
	tb, srv := newTable(t)
	dir := t.TempDir()
	j := journal.Open(dir, "0.4.0", "x")
	j.MaxSize = 4000 // force rotation into gzip archives
	write := func(from, to int) {
		for i := from; i < to; i++ {
			j.Write(journal.Event{Kind: journal.KindFinding, Sev: "HIGH", Title: "t", Note: fmt.Sprint(i)})
			time.Sleep(time.Millisecond) // archives are named to the millisecond
		}
	}
	write(0, 70)
	up := &Uploader{DataDir: dir, URL: srv.URL, MachineID: "m1", BatchSize: 25, MaxEvents: 60}
	if r := up.Run(); r.Err != nil || r.Sent != 60 || r.Waiting != 10 {
		t.Fatalf("first run: %+v", r)
	}
	// more events: the file that was active becomes an archive between runs
	before := len(journal.Archives(dir))
	write(70, 150)
	if len(journal.Archives(dir)) < before+2 {
		t.Fatal("expected further rotation")
	}
	for i := 0; i < 5; i++ {
		up.Run()
	}
	if len(tb.rows) != 150 || len(notes(tb)) != 150 {
		t.Fatalf("%d rows, %d distinct", len(tb.rows), len(notes(tb)))
	}
	st := up.loadState()
	if st.Sent != 150 || len(st.Archives) != len(journal.Archives(dir)) {
		t.Fatalf("state: %+v", st)
	}
	// uploaded archives are not opened again: a damaged old archive does not disturb later uploads
	first := journal.Archives(dir)[0]
	os.WriteFile(first, []byte("not gzip"), 0o600)
	write(150, 153)
	requests := len(tb.bodies)
	if r := up.Run(); r.Err != nil || r.Sent != 3 || len(tb.rows) != 153 || len(tb.bodies) != requests+1 {
		t.Fatalf("after damaging an uploaded archive: %+v rows=%d", r, len(tb.rows))
	}
	// while an archive is being compressed both forms exist; it must count once
	plain := strings.TrimSuffix(journal.Archives(dir)[1], ".gz")
	os.WriteFile(plain, []byte(`{"ts":"2026-10-01T10:00:00Z","kind":"guard"}`+"\n"), 0o600)
	for _, p := range journal.Archives(dir) {
		if p == plain+".gz" {
			t.Fatal("the gzip twin of a plain archive must not be listed")
		}
	}
	os.Remove(plain)
	// a journal that was wiped starts over instead of waiting for the old count
	for _, p := range journal.Archives(dir) {
		os.Remove(p)
	}
	os.Remove(filepath.Join(dir, journal.FileName))
	journal.Open(dir, "0.4.0", "x").Write(journal.Event{Kind: journal.KindGuard, Title: "fresh", Note: "fresh"})
	if r := up.Run(); r.Err != nil || r.Sent != 1 || !notes(tb)["fresh"] {
		t.Fatalf("after a journal reset: %+v", r)
	}
}

func TestUploadedRowsAreRedacted(t *testing.T) {
	tb, srv := newTable(t)
	dir := t.TempDir()
	j := journal.Open(dir, "0.4.0", "2026.10.01.1")
	no := false
	// every secret here is made up for the test
	j.Write(journal.Event{Kind: journal.KindFinding, Sev: "CRITICAL", Category: "malicious_process", Threat: "Behavior:Node/PolinRider.Payload",
		Title: "PID 5 (node) started by faheem", Path: "/home/faheem/secret-repo/postcss.config.mjs", PID: 5,
		Cmd:     "node /home/faheem/secret-repo/x.js --token=abcdef123456 ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000",
		Matched: "global['_V']\x00='8-st17'", Why: "found in /home/faheem/secret-repo on fedora-box", Response: "killed; see /home/faheem/.pushwarden/quarantine",
		Action: "killed PID 5", OK: &no, Evidence: []string{"line 3 of /home/faheem/secret-repo/x.js", "https://bob:s3cr3tpw@github.com/x/y.git"},
		Sweep: "s1", Key: "malicious_process|PID 5|/home/faheem/secret-repo/x.js", Note: "password: hunter2secret",
		Data: map[string]any{"roots": []any{"/home/faheem/Coding", "/home/faheem/src"}, "seconds": 12,
			"nested": map[string]any{"cwd": "/home/faheem/secret-repo", "key": "AKIAIOSFODNN7EXAMPLE"},
			"jwt":    "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJlLWZha2UtZmFrZQ", "sb": "sb_publishable_FAKEfakeFAKEfake1234"}})
	up := &Uploader{DataDir: dir, URL: srv.URL, Key: "anon-key", MachineID: "m1", OS: "linux",
		Red: &Redactor{Home: "/home/faheem", User: "faheem", Host: "fedora-box"}}
	preview, _ := up.Pending(5)
	pj, _ := json.Marshal(preview)
	if r := up.Run(); r.Err != nil || r.Sent != 1 {
		t.Fatalf("%+v", r)
	}
	body := tb.bodies[0]
	if string(pj) != body {
		t.Fatalf("the preview differs from what was sent:\n%s\n%s", pj, body)
	}
	for _, leak := range []string{"/home/faheem", "faheem", "fedora-box", "abcdef123456", "ghp_FAKE", "s3cr3tpw", "hunter2secret", "AKIAIOSFODNN7EXAMPLE",
		"eyJhbGci", "sb_publishable_FAKE", `\u0000`, "anon-key"} {
		if strings.Contains(body, leak) {
			t.Errorf("request body leaks %q:\n%s", leak, body)
		}
	}
	for _, keep := range []string{`"path":"~/secret-repo/postcss.config.mjs"`, `"machine_id":"m1"`, `"os":"linux"`, `"sev":"CRITICAL"`, `"ok":false`,
		`"matched":"global['_V']='8-st17'"`, `"finding_key":"malicious_process|PID 5|~/secret-repo/x.js"`, `"~/Coding"`, `"cwd":"~/secret-repo"`, `"seconds":12`,
		`"threat":"Behavior:Node/PolinRider.Payload"`, `"sweep":"s1"`} {
		if !strings.Contains(body, keep) {
			t.Errorf("request body lacks %s:\n%s", keep, body)
		}
	}
}

func TestUploadRefusesPlainHTTPAndRedirects(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://abc.supabase.co/rest/v1/pushwarden_events": true,
		"http://127.0.0.1:54321/rest/v1/pushwarden_events":  true,
		"http://localhost:3000/t":                           true,
		"http://abc.supabase.co/rest/v1/pushwarden_events":  false,
		"ftp://x/y":       false,
		"abc.supabase.co": false,
		"":                false,
	} {
		if (CheckURL(raw) == nil) != ok {
			t.Errorf("CheckURL(%q) ok=%v, want %v", raw, !ok, ok)
		}
	}
	dir := journalWith(t, 3)
	up := &Uploader{DataDir: dir, URL: "http://example.com/t", Key: "k", MachineID: "m"}
	if r := up.Run(); r.Err == nil || r.Sent != 0 || r.Waiting != 3 {
		t.Fatal("plain http to another host must be refused")
	}
	// a redirect is an error, and the key does not follow it
	var got []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = append(got, r.Header.Get("apikey")) }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	up.URL = redir.URL
	if r := up.Run(); r.Err == nil || r.Sent != 0 || len(got) != 0 {
		t.Fatalf("redirect followed: %+v other saw %v", r, got)
	}
	// no URL: nothing happens
	up.URL = ""
	if r := up.Run(); r.Sent != 0 || r.Err != nil || up.Due(time.Now()) {
		t.Fatal("no upload_url must mean no upload")
	}
}

func TestPruningJournalArchivesDoesNotDisturbTheUpload(t *testing.T) {
	tb, srv := newTable(t)
	dir := t.TempDir()
	j := journal.Open(dir, "0.4.0", "x")
	j.MaxSize = 4000
	write := func(from, to int) {
		for i := from; i < to; i++ {
			j.Write(journal.Event{Kind: journal.KindFinding, Sev: "HIGH", Title: "t", Note: fmt.Sprint(i)})
			time.Sleep(time.Millisecond)
		}
	}
	write(0, 120)
	up := &Uploader{DataDir: dir, URL: srv.URL, MachineID: "m1"}
	if r := up.Run(); r.Err != nil || r.Sent != 120 {
		t.Fatalf("%+v", r)
	}
	write(120, 150) // waiting
	arch := journal.Archives(dir)
	if len(arch) < 4 {
		t.Fatalf("archives: %d", len(arch))
	}
	if up.Unsent(arch[0]) || !up.Unsent(arch[len(arch)-1]) {
		t.Fatal("the first archive is uploaded, the last one holds waiting events")
	}
	ids := map[string]string{} // note -> event id, before pruning
	for id, row := range tb.rows {
		ids[row["note"].(string)] = id
	}
	// housekeeping deletes the two oldest archives
	var limit int64
	for _, a := range arch[2:] {
		fi, _ := os.Stat(a)
		limit += fi.Size()
	}
	p := journal.Prune(dir, limit, 0, up.Unsent, false, time.Now())
	if p.Files != 2 || p.Unsent != 0 || journal.PrunedEvents(dir) != p.Events || len(journal.Archives(dir)) != len(arch)-p.Files {
		t.Fatalf("prune: %+v", p)
	}
	// what is left keeps its state: nothing uploaded turns into waiting or the reverse
	evs := journal.Read(dir, journal.Filter{Archives: true})
	up.Mark(evs)
	if got := states(evs); got != strings.Repeat("U", 120-p.Events)+strings.Repeat("w", 30) {
		t.Fatalf("flags after pruning (%d events pruned): %s", p.Events, got)
	}
	if st := up.Status(); st.Uploaded != 120 || st.Waiting != 30 {
		t.Fatalf("status after pruning: %+v", st)
	}
	// the next run sends only the waiting events, under the ids they would have had anyway
	requests := len(tb.bodies)
	if r := up.Run(); r.Err != nil || r.Sent != 30 || len(tb.bodies) != requests+1 || len(tb.rows) != 150 {
		t.Fatalf("after pruning: %+v rows=%d", r, len(tb.rows))
	}
	for id, row := range tb.rows {
		if old, ok := ids[row["note"].(string)]; ok && old != id {
			t.Fatal("an event id changed after pruning")
		}
	}
	// even with the upload state lost, the surviving events get their old ids: no duplicates
	os.Remove(up.statePath())
	if r := up.Run(); r.Err != nil || len(tb.rows) != 150 {
		t.Fatalf("resend after pruning: %+v rows=%d", r, len(tb.rows))
	}
}

func TestLongBacklogIsSentInSlices(t *testing.T) {
	tb, srv := newTable(t)
	dir := journalWith(t, 4500) // more than two slices
	up := &Uploader{DataDir: dir, URL: srv.URL, MachineID: "m1"}
	r := up.Run()
	if r.Err != nil || r.Sent != 4500 || r.Waiting != 0 || len(tb.rows) != 4500 || len(notes(tb)) != 4500 {
		t.Fatalf("%+v rows=%d", r, len(tb.rows))
	}
	up2 := &Uploader{DataDir: journalWith(t, 4500), URL: srv.URL, MachineID: "m2", MaxEvents: 2500}
	if r := up2.Run(); r.Err != nil || r.Sent != 2500 || r.Waiting != 2000 {
		t.Fatalf("limited run: %+v", r)
	}
}
