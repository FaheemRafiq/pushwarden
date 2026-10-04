package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
)

// StateFile holds github-clean's progress in the data directory.
const StateFile = "github-clean-state.json"

// BranchState is a finished result for one branch, valid for one commit.
//
// PolinRider force-pushes with a stolen token, so "this branch was cleaned
// yesterday" proves nothing about today. What is remembered is "commit SHA
// was verified": a branch is skipped only while its tip is still that commit.
type BranchState struct {
	SHA      string              `json:"sha"`    // branch tip after processing: the commit that was scanned, or the fix that was pushed
	Status   string              `json:"status"` // clean, pushed or manual; unfinished results are never remembered
	Commit   string              `json:"commit,omitempty"`
	Fixed    []string            `json:"fixed,omitempty"`
	Findings []*findings.Finding `json:"findings,omitempty"`
	At       string              `json:"at"`
}

// RepoState is what is remembered about one repository. It counts only for
// the indicator and program versions that produced it: newer ones may find
// what the older missed.
type RepoState struct {
	Branches map[string]BranchState `json:"branches"`
	History  []*findings.Finding    `json:"history,omitempty"`
	IOCs     string                 `json:"iocs"`
	Ver      string                 `json:"ver"`
}

// State is github-clean's memory across runs. It is saved after every
// branch, so a run that is interrupted, killed or loses power continues where
// it stopped. It holds no token and no clone URL.
type State struct {
	Repos map[string]*RepoState `json:"repos"`

	path string
	mu   sync.Mutex
}

// LoadState reads the progress file; a missing or damaged one is an empty state.
func LoadState(dataDir string) *State {
	s := &State{path: filepath.Join(dataDir, StateFile)}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, s)
	}
	if s.Repos == nil {
		s.Repos = map[string]*RepoState{}
	}
	return s
}

func (s *State) save() {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// Reset forgets everything, so the next run checks every branch, and removes
// the kept clones.
func (s *State) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Repos = map[string]*RepoState{}
	s.save()
	_ = os.RemoveAll(s.clonesDir())
}

// ClonesDir is the folder in the data directory holding kept clones.
const ClonesDir = "github-clean-clones"

// CloneMaxAge is how long a kept clone waits for its --apply by default
// (config: clone_keep_days).
const CloneMaxAge = 3 * 24 * time.Hour

// StateMaxAge is how long a repository that was not looked at again stays in
// the progress file.
const StateMaxAge = 90 * 24 * time.Hour

func (s *State) clonesDir() string { return filepath.Join(filepath.Dir(s.path), ClonesDir) }

// clonePath is where the clone of one repository is kept while it still has
// branches to fix, so the run that fixes them does not download it again.
func (s *State) clonePath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.clonesDir(), safeName(key)+"-"+hex.EncodeToString(sum[:4]))
}

// PruneClones removes kept clones that were not used for maxAge, then the
// least recently used ones while together they exceed maxBytes; zero disables
// a limit. It returns how many were removed and their size.
func (s *State) PruneClones(maxAge time.Duration, maxBytes int64, dry bool) (int, int64) {
	type clone struct {
		path string
		at   time.Time
		size int64
	}
	var all []clone
	var total int64
	ents, _ := os.ReadDir(s.clonesDir())
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil || !e.IsDir() {
			continue
		}
		c := clone{filepath.Join(s.clonesDir(), e.Name()), fi.ModTime(), 0}
		c.size = treeSize(c.path)
		total += c.size
		all = append(all, c)
	}
	sort.Slice(all, func(a, b int) bool { return all[a].at.Before(all[b].at) })
	n, freed := 0, int64(0)
	for _, c := range all {
		if !(maxAge > 0 && time.Since(c.at) > maxAge) && !(maxBytes > 0 && total > maxBytes) {
			continue
		}
		if dry || os.RemoveAll(c.path) == nil {
			n++
			freed += c.size
			total -= c.size
		}
	}
	if !dry {
		if left, _ := os.ReadDir(s.clonesDir()); len(left) == 0 {
			_ = os.Remove(s.clonesDir())
		}
	}
	return n, freed
}

// DropStale forgets repositories nothing was verified in for maxAge: they
// were deleted, renamed, or are no longer reachable with this token.
func (s *State) DropStale(maxAge time.Duration, dry bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, rs := range s.Repos {
		last := ""
		for _, b := range rs.Branches {
			if b.At > last {
				last = b.At
			}
		}
		t, err := time.Parse(time.RFC3339, last)
		if err == nil && time.Since(t) <= maxAge {
			continue
		}
		n++
		if !dry {
			delete(s.Repos, key)
		}
	}
	if n > 0 && !dry {
		s.save()
	}
	return n
}

func treeSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// Clones reports how many clones are kept and their size on disk.
func (s *State) Clones() (n int, bytes int64) {
	ents, _ := os.ReadDir(s.clonesDir())
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		n++
		bytes += treeSize(filepath.Join(s.clonesDir(), e.Name()))
	}
	return
}

// repo returns what is remembered for key under these versions. Results made
// with other indicators or another program version are discarded.
func (s *State) repo(key, iocs, ver string) *RepoState {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.Repos[key]
	if rs == nil || rs.IOCs != iocs || rs.Ver != ver || rs.Branches == nil {
		rs = &RepoState{Branches: map[string]BranchState{}, IOCs: iocs, Ver: ver}
		s.Repos[key] = rs
	}
	return rs
}

// record remembers a finished branch, or forgets one that is not finished.
func (s *State) record(rs *RepoState, br Branch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case br.SHA != "" && (br.Status == StatusClean || br.Status == StatusPushed || br.Status == StatusManual):
		bs := BranchState{SHA: br.SHA, Status: br.Status, Commit: br.Commit, Fixed: br.Fixed, At: time.Now().Format(time.RFC3339)}
		if br.Status == StatusManual {
			bs.Findings = br.Findings // what to review; other results need no details kept
		}
		rs.Branches[br.Name] = bs
	default:
		delete(rs.Branches, br.Name)
	}
	s.save()
}

// keep drops remembered branches that no longer exist on the remote.
func (s *State) keep(rs *RepoState, exists map[string]string, history []*findings.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range rs.Branches {
		if _, ok := exists[name]; !ok {
			delete(rs.Branches, name)
		}
	}
	rs.History = history
	s.save()
}

// reuse returns the remembered result for a branch whose tip is still the
// verified commit.
func (rs *RepoState) reuse(name, tip string) (Branch, bool) {
	b, ok := rs.Branches[name]
	if !ok || tip == "" || b.SHA != tip {
		return Branch{}, false
	}
	return Branch{Name: name, Status: b.Status, Commit: b.Commit, Fixed: b.Fixed, Findings: b.Findings, SHA: b.SHA, Resumed: true, At: b.At}, true
}

// Progress summarises what is remembered, for `github-clean --progress`.
type Progress struct {
	Repo                  string
	Clean, Pushed, Manual int
	Last                  string
	IOCs, Ver             string
}

func (s *State) Progress() []Progress {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Progress
	for key, rs := range s.Repos {
		p := Progress{Repo: key, IOCs: rs.IOCs, Ver: rs.Ver}
		for _, b := range rs.Branches {
			switch b.Status {
			case StatusClean:
				p.Clean++
			case StatusPushed:
				p.Pushed++
			case StatusManual:
				p.Manual++
			}
			if b.At > p.Last {
				p.Last = b.At
			}
		}
		if p.Clean+p.Pushed+p.Manual > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out
}
