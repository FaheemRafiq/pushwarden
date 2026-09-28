package docs

import (
	"regexp"
	"strings"
)

// Style colours a piece of text; the terminal UI supplies one, tests pass nil.
type Style func(kind, s string) string

var (
	inlineCode = regexp.MustCompile("`([^`]*)`")
	bold       = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	link       = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
)

func plain(s string) string {
	s = link.ReplaceAllStringFunc(s, func(m string) string {
		p := link.FindStringSubmatch(m)
		if strings.HasPrefix(p[2], "#") {
			return p[1]
		}
		return p[1] + " (" + p[2] + ")"
	})
	s = bold.ReplaceAllString(s, "$1")
	s = inlineCode.ReplaceAllString(s, "$1")
	return s
}

// Render turns the markdown subset used in CLI.md (headings, paragraphs,
// lists, fenced code, pipe tables) into terminal text of the given width.
func Render(md string, width int, st Style) string {
	if st == nil {
		st = func(_, s string) string { return s }
	}
	if width < 40 {
		width = 40
	}
	var out []string
	var para []string
	var table [][]string
	inCode := false
	flushPara := func() {
		if len(para) > 0 {
			out = append(out, wrap(plain(strings.Join(para, " ")), width, "")...)
			out = append(out, "")
			para = nil
		}
	}
	flushTable := func() {
		if len(table) > 0 {
			out = append(out, renderTable(table, width, st)...)
			out = append(out, "")
			table = nil
		}
	}
	for _, l := range strings.Split(md, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "```"):
			flushPara()
			flushTable()
			inCode = !inCode
			if !inCode {
				out = append(out, "")
			}
		case inCode:
			out = append(out, st("code", "    "+l))
		case strings.HasPrefix(t, "|"):
			flushPara()
			if strings.Trim(t, "|-: ") == "" {
				continue // separator row
			}
			cells := strings.Split(strings.Trim(t, "|"), "|")
			for i := range cells {
				cells[i] = plain(strings.TrimSpace(cells[i]))
			}
			table = append(table, cells)
		case strings.HasPrefix(t, "#"):
			flushPara()
			flushTable()
			out = append(out, st("heading", strings.TrimSpace(strings.TrimLeft(t, "#"))), "")
		case strings.HasPrefix(t, "- ") || numbered(t):
			flushPara()
			flushTable()
			marker, rest, _ := strings.Cut(t, " ")
			out = append(out, wrap(plain(rest), width-4, "  "+marker+" ")...)
		case t == "":
			flushPara()
			flushTable()
		case strings.HasPrefix(t, "<!--"):
		default:
			flushTable()
			para = append(para, t)
		}
	}
	flushPara()
	flushTable()
	// collapse runs of blank lines
	var res []string
	for _, l := range out {
		if l == "" && len(res) > 0 && res[len(res)-1] == "" {
			continue
		}
		res = append(res, l)
	}
	return strings.TrimRight(strings.Join(res, "\n"), "\n") + "\n"
}

func numbered(t string) bool {
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	return i > 0 && i+1 < len(t) && t[i] == '.' && t[i+1] == ' '
}

// wrap breaks text at spaces; the first line gets prefix, later lines the same indent.
func wrap(text string, width int, prefix string) []string {
	indent := strings.Repeat(" ", len(prefix))
	var lines []string
	cur := prefix
	curLen := len(prefix)
	first := true
	for _, w := range strings.Fields(text) {
		if !first && curLen+1+len(w) > width {
			lines = append(lines, cur)
			cur, curLen = indent+w, len(indent)+len(w)
			continue
		}
		if first {
			cur += w
			curLen += len(w)
			first = false
		} else {
			cur += " " + w
			curLen += 1 + len(w)
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// renderTable prints the first column as a label and wraps the rest beside it.
func renderTable(rows [][]string, width int, st Style) []string {
	cols := 0
	for _, r := range rows {
		cols = max(cols, len(r))
	}
	if cols == 0 {
		return nil
	}
	widths := make([]int, cols)
	for _, r := range rows {
		for i, c := range r {
			widths[i] = max(widths[i], len(c))
		}
	}
	// last column takes whatever is left; keep the others at their natural width (capped)
	label := 0
	for i := 0; i < cols-1; i++ {
		widths[i] = min(widths[i], 28)
		label += widths[i] + 2
	}
	rest := max(width-2-label, 20)
	var out []string
	for ri, r := range rows {
		for len(r) < cols {
			r = append(r, "")
		}
		var head strings.Builder
		head.WriteString("  ")
		for i := 0; i < cols-1; i++ {
			c := r[i]
			if len(c) > widths[i] {
				c = c[:widths[i]-1] + "…"
			}
			pad := strings.Repeat(" ", widths[i]-len(c)+2)
			if ri == 0 {
				head.WriteString(st("heading", c) + pad)
			} else {
				head.WriteString(st("label", c) + pad)
			}
		}
		lines := wrap(r[cols-1], rest, "")
		if len(lines) == 0 {
			lines = []string{""}
		}
		if ri == 0 {
			lines[0] = st("heading", lines[0])
		}
		out = append(out, head.String()+lines[0])
		for _, l := range lines[1:] {
			out = append(out, strings.Repeat(" ", 2+label)+l)
		}
	}
	return out
}
