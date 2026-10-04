package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataDirKeepsTheOldFolder(t *testing.T) {
	t.Setenv("PUSHWARDEN_HOME", "")
	home := t.TempDir()
	p := &Info{Home: home}
	now, old := filepath.Join(home, ".pushwarden"), filepath.Join(home, LegacyDataDirName)
	if got := p.DataDir(); got != now {
		t.Fatalf("a new user gets the new folder, got %s", got)
	}
	os.Mkdir(old, 0o700)
	if got := p.DataDir(); got != old {
		t.Fatalf("only the old folder exists: it is used, got %s", got)
	}
	os.Mkdir(now, 0o700)
	if got := p.DataDir(); got != now {
		t.Fatalf("both exist: the new folder wins, got %s", got)
	}
	t.Setenv("PUSHWARDEN_HOME", "/elsewhere")
	if got := p.DataDir(); got != "/elsewhere" {
		t.Fatalf("PUSHWARDEN_HOME overrides both, got %s", got)
	}
}
