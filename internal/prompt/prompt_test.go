// pushwarden:allow-signatures
package prompt

import (
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
)

func TestBuildMessage(t *testing.T) {
	f := &findings.Finding{Severity: findings.Critical, Category: "fake_font_loader",
		Title: "Font file contains code: fa-solid-900.woff2", Path: "/r/public/fonts/fa-solid-900.woff2",
		Meta: findings.Meta{Evidence: []string{"woff2 extension but content is JavaScript", "campaign marker global['!']"}}}
	msg := BuildMessage(f, "Delete the file")
	for _, want := range []string{"Evidence:", "campaign marker", "permanently", f.Path} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if m := BuildMessage(f, "Remove payload"); strings.Contains(m, "permanently") || !strings.Contains(m, "restored") {
		t.Errorf("reversible action message:\n%s", m)
	}
}

func TestDialogDeleteAtTimeoutIsTimeout(t *testing.T) {
	const timeout = 1 * time.Second
	// answered in time: honoured
	restore := SetDialogForTest(func(_, _, _, _ string, _ time.Duration) Verdict { return Delete })
	if v := Dialog("t", "m", "Delete", "Keep", timeout); v != Delete {
		t.Errorf("prompt Delete: got %s", v)
	}
	restore()
	// "Delete" that arrives when the dialog would have timed out: nobody answered
	restore = SetDialogForTest(func(_, _, _, _ string, d time.Duration) Verdict {
		time.Sleep(d)
		return Delete
	})
	defer restore()
	if v := Dialog("t", "m", "Delete", "Keep", timeout); v != Timeout {
		t.Errorf("Delete at the timeout boundary: got %s, want timeout", v)
	}
	// a late Keep is still a Keep (nothing destructive happens)
	SetDialogForTest(func(_, _, _, _ string, d time.Duration) Verdict { time.Sleep(d); return Keep })
	if v := Dialog("t", "m", "Delete", "Keep", timeout); v != Keep {
		t.Errorf("late Keep: got %s", v)
	}
}
