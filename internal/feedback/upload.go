package feedback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/journal"
)

// Row is one journal event as stored in the central table. Every text field
// is redacted before it leaves the machine.
type Row struct {
	EventID   string         `json:"event_id"` // stable: the table skips a row it already holds
	MachineID string         `json:"machine_id"`
	TS        string         `json:"ts"`
	Ver       string         `json:"ver"`
	IOCs      string         `json:"iocs"`
	OS        string         `json:"os"`
	Ctx       string         `json:"ctx"`
	Kind      string         `json:"kind"`
	Sev       *string        `json:"sev"`
	Category  *string        `json:"category"`
	Threat    *string        `json:"threat"`
	Title     *string        `json:"title"`
	Path      *string        `json:"path"`
	Cmd       *string        `json:"cmd"`
	Matched   *string        `json:"matched"`
	Why       *string        `json:"why"`
	Response  *string        `json:"response"`
	Action    *string        `json:"action"`
	OK        *bool          `json:"ok"`
	Evidence  []string       `json:"evidence"`
	Sweep     *string        `json:"sweep"`
	Key       *string        `json:"finding_key"`
	Note      *string        `json:"note"`
	Data      map[string]any `json:"data"`
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ToRow converts and redacts one event. ord is the event's position in the
// machine's journal: it makes the id unique, and the same on every retry.
func ToRow(e journal.Event, machineID, goos string, ord int, red *Redactor) Row {
	r := func(s string) string {
		if red != nil {
			s = red.Text(s)
		}
		// Postgres stores neither NUL bytes in text nor \u0000 in jsonb; one
		// such byte in matched text would reject the whole batch forever.
		return strings.ReplaceAll(s, "\x00", "")
	}
	sum := sha256.Sum256([]byte(machineID + "|" + strconv.Itoa(ord) + "|" + e.TS + "|" + e.Kind))
	row := Row{EventID: hex.EncodeToString(sum[:12]), MachineID: machineID, TS: e.TS, Ver: e.Ver, IOCs: e.IOCs, OS: goos, Ctx: e.Ctx, Kind: e.Kind,
		Sev: opt(e.Sev), Category: opt(e.Category), Threat: opt(r(e.Threat)), Title: opt(r(e.Title)), Path: opt(r(e.Path)), Cmd: opt(r(e.Cmd)),
		Matched: opt(r(e.Matched)), Why: opt(r(e.Why)), Response: opt(r(e.Response)), Action: opt(r(e.Action)), OK: e.OK,
		Sweep: opt(e.Sweep), Key: opt(r(e.Key)), Note: opt(r(e.Note))}
	for _, ev := range e.Evidence {
		row.Evidence = append(row.Evidence, r(ev))
	}
	if len(e.Data) > 0 {
		row.Data, _ = redactValue(e.Data, r).(map[string]any)
	}
	return row
}

// redactValue applies r to every string inside a decoded JSON value.
func redactValue(v any, r func(string) string) any {
	switch x := v.(type) {
	case string:
		return r(x)
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = redactValue(el, r)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			out[k] = redactValue(el, r)
		}
		return out
	}
	return v
}

// Uploader pushes new journal events to a central table over HTTPS. It is
// written for Supabase's REST API (apikey + Bearer headers, a JSON array per
// POST) and works with any endpoint that accepts the same.
type Uploader struct {
	DataDir   string
	URL       string // e.g. https://PROJECT.supabase.co/rest/v1/threatscan_events
	Key       string // an insert-only key; it lives in every install's config
	MachineID string
	OS        string
	Red       *Redactor
	BatchSize int           // rows per request (default 200)
	MaxEvents int           // per run (default 20000), so one run stays bounded
	Timeout   time.Duration // for one whole run (default 5 minutes)
	HTTP      *http.Client
}

// State is the upload's memory, kept in upload-state.json.
//
// The journal is append-only and its archives never change, so every event
// has a fixed position: archives in name order, then the active file. Sent
// is how many events, counted from the first, are stored at the URL. Event i
// is uploaded when i < Sent and waiting otherwise. Timestamps play no part,
// so a clock change cannot hide an event.
type State struct {
	URL          string         `json:"url"`                     // fingerprint of the upload_url that Sent refers to
	Sent         int            `json:"sent"`                    // events uploaded, in journal order
	Archives     map[string]int `json:"archives,omitempty"`      // events per rotated archive, so old ones are not reopened
	Synced       string         `json:"synced,omitempty"`        // what the journal looked like when nothing was waiting
	LastAttempt  string         `json:"last_attempt,omitempty"`  // RFC 3339
	LastSuccess  string         `json:"last_success,omitempty"`  // last run that reached the server and was accepted
	LastError    string         `json:"last_error,omitempty"`    // why the latest run failed; empty after a success
	FailingSince string         `json:"failing_since,omitempty"` // first failure of the current streak
	Failures     int            `json:"failures,omitempty"`      // consecutive failed runs
}

func (u *Uploader) statePath() string { return filepath.Join(u.DataDir, "upload-state.json") }

func urlMark(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

// loadState returns the state as it applies to the configured URL. A state
// written for another URL counts for nothing: the new destination has
// received no event yet.
func (u *Uploader) loadState() State {
	var st State
	if b, err := os.ReadFile(u.statePath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if mark := urlMark(u.URL); st.URL != mark {
		st = State{URL: mark, Archives: st.Archives}
	}
	if st.Archives == nil {
		st.Archives = map[string]int{}
	}
	if st.Sent < 0 {
		st.Sent = 0
	}
	return st
}

func (u *Uploader) saveState(st State) error {
	b, _ := json.Marshal(st)
	tmp := u.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.statePath())
}

// journalMark describes the journal cheaply: it changes whenever an event is
// added or a file is rotated.
func (u *Uploader) journalMark() string {
	var size int64
	if fi, err := os.Stat(filepath.Join(u.DataDir, journal.FileName)); err == nil {
		size = fi.Size()
	}
	return strconv.Itoa(len(journal.Archives(u.DataDir))) + "/" + strconv.FormatInt(size, 10)
}

type pendingRow struct {
	row  Row
	next int // Sent once this row is stored
}

// scan walks the journal from the first event that is not uploaded. It
// returns up to limit rows to send, how many events wait in total, and how
// many events the journal holds. st.Archives is filled in for archives read.
func (u *Uploader) scan(st *State, limit int) (rows []pendingRow, waiting, total int) {
	files := journal.Archives(u.DataDir)
	nArch := len(files)
	files = append(files, filepath.Join(u.DataDir, journal.FileName))
	for pass := 0; pass < 2; pass++ {
		// events of archives deleted to save space still count: positions never shift
		rows, waiting, total = nil, 0, journal.PrunedEvents(u.DataDir)
		known := map[string]bool{}
		for i, p := range files {
			name := journal.ArchiveName(p)
			if i < nArch {
				known[name] = true
				if n, ok := st.Archives[name]; ok && total+n <= st.Sent {
					total += n // wholly uploaded: no need to open it
					continue
				}
			}
			evs := journal.ReadFile(p)
			if i < nArch {
				st.Archives[name] = len(evs)
			}
			for j, e := range evs {
				ord := total + j
				if ord < st.Sent || e.Time().IsZero() { // no usable timestamp: the table would reject the batch
					continue
				}
				waiting++
				if len(rows) < limit {
					rows = append(rows, pendingRow{ToRow(e, u.MachineID, u.OS, ord, u.Red), ord + 1})
				}
			}
			total += len(evs)
		}
		for name := range st.Archives {
			if !known[name] {
				delete(st.Archives, name)
			}
		}
		if total >= st.Sent {
			break
		}
		st.Sent = 0 // the journal is shorter than what was sent: it was reset, so start over
	}
	return rows, waiting, total
}

// Pending returns the next rows that would be uploaded (at most limit) and
// how many events are waiting in total. It sends nothing and saves nothing.
func (u *Uploader) Pending(limit int) ([]Row, int) {
	st := u.loadState()
	prs, waiting, _ := u.scan(&st, limit)
	rows := make([]Row, len(prs))
	for i, p := range prs {
		rows[i] = p.row
	}
	return rows, waiting
}

// Status is where the upload stands, for `status` and the logs.
type Status struct {
	Uploaded, Waiting int
	LastSuccess       time.Time
	FailingSince      time.Time
	LastError         string
	Failures          int
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// Status reads the state and counts what is waiting.
func (u *Uploader) Status() Status {
	st := u.loadState()
	_, waiting, total := u.scan(&st, 0)
	return Status{Uploaded: total - waiting, Waiting: waiting, LastSuccess: parseTime(st.LastSuccess),
		FailingSince: parseTime(st.FailingSince), LastError: st.LastError, Failures: st.Failures}
}

// Mark sets Uploaded on each event read from this machine's journal.
func (u *Uploader) Mark(evs []journal.Event) {
	st := u.loadState()
	base, total := map[string]int{}, journal.PrunedEvents(u.DataDir)
	for _, p := range journal.Archives(u.DataDir) {
		name := journal.ArchiveName(p)
		n, ok := st.Archives[name]
		if !ok {
			n = len(journal.ReadFile(p))
			st.Archives[name] = n
		}
		base[name] = total
		total += n
	}
	base[journal.FileName] = total
	for i := range evs {
		b, ok := base[evs[i].File]
		done := ok && b+evs[i].Line < st.Sent
		evs[i].Uploaded = &done
	}
}

// Unsent reports whether a journal archive still holds events that are not
// uploaded, so housekeeping keeps it a while longer.
func (u *Uploader) Unsent(archive string) bool {
	if u.URL == "" {
		return false
	}
	st := u.loadState()
	total := journal.PrunedEvents(u.DataDir)
	want := journal.ArchiveName(archive)
	for _, p := range journal.Archives(u.DataDir) {
		name := journal.ArchiveName(p)
		n, ok := st.Archives[name]
		if !ok {
			n = len(journal.ReadFile(p))
		}
		total += n
		if name == want {
			return total > st.Sent
		}
	}
	return false
}

// Due reports whether the guard should run an upload now. It is cheap: two
// small files are looked at, the journal is not read.
//
// Nothing new since the last complete upload: no. Otherwise every 10
// minutes. After a failure the next tries come after 1, 2, 4 and 8 minutes,
// then every 10, so a machine that is back online delivers soon.
func (u *Uploader) Due(now time.Time) bool {
	if u.URL == "" {
		return false
	}
	st := u.loadState()
	last := parseTime(st.LastAttempt)
	if st.Failures > 0 {
		wait := 10 * time.Minute
		if st.Failures <= 4 {
			wait = time.Minute << (st.Failures - 1)
		}
		return now.Sub(last) >= wait
	}
	if st.Synced != "" && st.Synced == u.journalMark() {
		return false
	}
	return last.IsZero() || now.Sub(last) >= 10*time.Minute
}

// CheckURL accepts https, and plain http only towards this machine itself:
// the key and the events must not cross a network unencrypted.
func CheckURL(raw string) error {
	p, err := url.Parse(raw)
	if err != nil || p.Host == "" {
		return errors.New("upload_url is not a valid URL")
	}
	switch p.Scheme {
	case "https":
		return nil
	case "http":
		h := p.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("upload_url must start with https://")
}

func (u *Uploader) client() *http.Client {
	if u.HTTP != nil {
		return u.HTTP
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		// A redirect would carry the key to another host; treat it as an error instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// errDuplicate is the table's answer to a row it already holds, when it does
// not skip such rows itself.
var errDuplicate = errors.New("already stored")

// post stores a batch. A batch can arrive twice: when the answer to the first
// attempt was lost, the cursor did not move. docs/supabase.sql makes the
// table skip rows it already has. A table without that rule answers 409 for
// the whole batch; the rows are then sent one by one and a 409 for a single
// row means it is stored.
func (u *Uploader) post(ctx context.Context, rows []Row) error {
	err := u.send(ctx, rows)
	if err != errDuplicate {
		return err
	}
	for i := range rows {
		if err := u.send(ctx, rows[i:i+1]); err != nil && err != errDuplicate {
			return err
		}
	}
	return nil
}

func (u *Uploader) send(ctx context.Context, rows []Row) error {
	body, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "threatscan")
	req.Header.Set("Prefer", "return=minimal") // the key may insert, not read back
	if u.Key != "" {
		req.Header.Set("apikey", u.Key)
		req.Header.Set("Authorization", "Bearer "+u.Key)
	}
	resp, err := u.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err // without the URL, which names the project
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return errDuplicate
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// runChunk is how many events one run holds in memory at a time.
const runChunk = 2000

// Result is the outcome of one run.
type Result struct {
	Sent      int   // events stored by this run
	Waiting   int   // events still waiting afterwards
	Err       error // why the run stopped early
	Recovered bool  // this run succeeded after one or more failed ones
	Failures  int   // consecutive failed runs, this one included
}

// Run uploads what is waiting, batch by batch. An event counts as uploaded
// only once the server has accepted its batch; the state is saved after every
// batch, so an interrupted run loses nothing and repeats at most one batch,
// which the table then skips.
func (u *Uploader) Run() Result {
	if u.URL == "" {
		return Result{}
	}
	max, size, timeout := u.MaxEvents, u.BatchSize, u.Timeout
	if max <= 0 {
		max = 20000
	}
	if size <= 0 {
		size = 200
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	_ = os.Remove(filepath.Join(u.DataDir, "upload-cursor.json")) // the time-based position of early builds
	st := u.loadState()
	wasFailing := st.Failures > 0
	mark := u.journalMark() // taken before reading: events added meanwhile change it
	var res Result
	total := 0

	err := CheckURL(u.URL)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// A long backlog is read and sent a slice at a time, so a run needs the
	// same small amount of memory whether 20 or 20000 events are waiting.
	for {
		lim := max - res.Sent
		if lim > runChunk {
			lim = runChunk
		}
		var rows []pendingRow
		rows, res.Waiting, total = u.scan(&st, lim)
		if err != nil || len(rows) == 0 {
			break
		}
		for err == nil && len(rows) > 0 {
			n := size
			if n > len(rows) {
				n = len(rows)
			}
			batch := make([]Row, n)
			for i := range batch {
				batch[i] = rows[i].row
			}
			if err = u.post(ctx, batch); err != nil {
				break
			}
			st.Sent = rows[n-1].next
			res.Sent += n
			res.Waiting -= n
			rows = rows[n:]
			if e := u.saveState(st); e != nil {
				err = fmt.Errorf("sent, but the position could not be saved: %w", e)
			}
		}
		if err != nil || res.Sent >= max || res.Waiting == 0 {
			break
		}
	}
	now := time.Now().Format(time.RFC3339)
	st.LastAttempt = now
	if err != nil {
		st.Failures++
		st.LastError = err.Error()
		if st.FailingSince == "" {
			st.FailingSince = now
		}
		res.Err, res.Failures = err, st.Failures
	} else {
		if res.Waiting == 0 {
			st.Sent, st.Synced = total, mark // also steps over events that cannot be sent
		}
		st.LastSuccess, st.LastError, st.FailingSince, st.Failures = now, "", "", 0
		res.Recovered = wasFailing
	}
	if e := u.saveState(st); e != nil && res.Err == nil {
		res.Err = e
	}
	return res
}
