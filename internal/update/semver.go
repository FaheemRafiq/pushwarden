package update

import (
	"strconv"
	"strings"
)

// Withdrawn lists released versions that were renumbered away: 6.0.0 was the
// first Go release before numbering restarted at 0.1.0. An installed withdrawn
// version counts as older than any other, so reinstalling replaces it.
var Withdrawn = map[string]bool{"6.0.0": true}

// IsWithdrawn reports whether v (with or without a leading "v") was withdrawn.
func IsWithdrawn(v string) bool { return Withdrawn[strings.TrimPrefix(v, "v")] }

// CompareVersions compares two semantic versions ("v0.2.0", "0.2.0-rc1").
// A pre-release sorts before its release.
func CompareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	ac, apre, _ := strings.Cut(a, "-")
	bc, bpre, _ := strings.Cut(b, "-")
	an, bn := strings.Split(ac, "."), strings.Split(bc, ".")
	for i := 0; i < 3; i++ {
		if c := cmpInt(part(an, i), part(bn, i)); c != 0 {
			return c
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	ap, bp := strings.Split(apre, "."), strings.Split(bpre, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		x, ex := strconv.Atoi(ap[i])
		y, ey := strconv.Atoi(bp[i])
		switch {
		case ex == nil && ey == nil:
			if c := cmpInt(x, y); c != 0 {
				return c
			}
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		default:
			if c := strings.Compare(ap[i], bp[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(ap), len(bp))
}

func part(p []string, i int) int {
	if i >= len(p) {
		return 0
	}
	n, _ := strconv.Atoi(p[i])
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
