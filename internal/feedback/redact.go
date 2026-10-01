// Package feedback turns a machine's journal into something that can leave
// it: a redacted bundle the user sends by hand, and an opt-in daily digest
// of counts with no paths, command lines or file contents.
package feedback

import (
	"regexp"
	"strings"
)

// Redactor removes what identifies the person or opens their accounts:
// the home directory, user name, host name, and anything shaped like a secret.
type Redactor struct {
	Home, User, Host string
}

var secretRes = []*regexp.Regexp{
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

var (
	// key=value / "key": "value" pairs whose key says the value is a secret
	keyValRe = regexp.MustCompile(`(?i)((?:token|secret|password|passwd|api[_-]?key|authorization|bearer|webhook_url|feedback_url)["']?\s*[:=]\s*["']?)([^\s"',&}]{6,})`)
	// credentials inside a URL
	urlCredRe = regexp.MustCompile(`(://)[^/\s:@]+:[^/\s@]+@`)
)

// Text redacts one string.
func (r Redactor) Text(s string) string {
	for _, re := range secretRes {
		s = re.ReplaceAllString(s, "<redacted>")
	}
	s = keyValRe.ReplaceAllString(s, "${1}<redacted>")
	s = urlCredRe.ReplaceAllString(s, "${1}<redacted>@")
	if r.Home != "" && r.Home != "/" {
		s = strings.ReplaceAll(s, r.Home, "~")
		// the same path JSON-escaped (Windows backslashes)
		s = strings.ReplaceAll(s, strings.ReplaceAll(r.Home, `\`, `\\`), "~")
	}
	if len(r.Host) >= 3 {
		s = strings.ReplaceAll(s, r.Host, "<host>")
	}
	if len(r.User) >= 3 {
		s = userRe(r.User).ReplaceAllString(s, "${1}<user>${2}")
	}
	return s
}

// userRe matches the user name as a whole path component or word.
func userRe(user string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_.-])` + regexp.QuoteMeta(user) + `($|[^A-Za-z0-9_.-])`)
}
