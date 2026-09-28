// Package docs embeds the user documentation so `threatscan help <topic>`
// works offline. docs/CLI.md is the single source: edit it, rebuild.
package docs

import (
	_ "embed"
	"sort"
	"strings"
)

//go:embed CLI.md
var CLI string

// Topic is one section of CLI.md that `help` can show.
type Topic struct {
	Name    string   // what the user types
	Aliases []string // other names that reach the same section
	Title   string   // heading text
	Body    string   // markdown of the section, heading excluded
}

var extraTopics = map[string][]string{ // "## heading" -> topic name + aliases
	"Conventions":                          {"conventions"},
	"Quick start":                          {"quickstart", "quick-start", "start"},
	"Configuration keys":                   {"config-keys", "keys", "settings"},
	"Files and directories":                {"files", "paths", "directories"},
	"Environment variables":                {"environment", "env"},
	"Severities, actions and threat names": {"severities", "actions", "threats"},
	"Recipes":                              {"recipes", "examples"},
	"Troubleshooting":                      {"troubleshooting", "faq"},
}

// Topics parses CLI.md: every "### name" under Commands is a command topic
// (a heading like "history and restore" yields both names); the "##" sections
// listed in extraTopics are reference topics.
func Topics() []Topic {
	var out []Topic
	lines := strings.Split(CLI, "\n")
	flush := func(t *Topic, body []string) {
		if t == nil {
			return
		}
		t.Body = strings.TrimSpace(strings.Join(body, "\n"))
		out = append(out, *t)
	}
	var cur *Topic
	var body []string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "### "):
			flush(cur, body)
			title := strings.TrimSpace(l[4:])
			names := strings.Split(title, " and ")
			cur = &Topic{Name: names[0], Title: title}
			for _, n := range names[1:] {
				cur.Aliases = append(cur.Aliases, strings.TrimSpace(n))
			}
			body = nil
		case strings.HasPrefix(l, "## "):
			flush(cur, body)
			cur, body = nil, nil
			if names, ok := extraTopics[strings.TrimSpace(l[3:])]; ok {
				cur = &Topic{Name: names[0], Aliases: names[1:], Title: strings.TrimSpace(l[3:])}
			}
		case strings.HasPrefix(l, "# "), l == "---":
			flush(cur, body)
			cur, body = nil, nil
		default:
			if cur != nil {
				body = append(body, l)
			}
		}
	}
	flush(cur, body)
	return out
}

// Lookup finds a topic by name or alias (case-insensitive). ok=false when unknown.
func Lookup(name string) (Topic, bool) {
	name = strings.ToLower(strings.TrimLeft(name, "-"))
	for _, t := range Topics() {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
		for _, a := range t.Aliases {
			if strings.EqualFold(a, name) {
				return t, true
			}
		}
	}
	return Topic{}, false
}

// Names lists every topic name, commands first in document order, then references sorted.
func Names() (commands, references []string) {
	for _, t := range Topics() {
		if _, ref := extraTopics[t.Title]; ref {
			references = append(references, t.Name)
		} else {
			commands = append(commands, t.Name)
			commands = append(commands, t.Aliases...)
		}
	}
	sort.Strings(references)
	return
}
