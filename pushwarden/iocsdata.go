// Package iocsdata embeds the indicator database shared by the Python and Go
// implementations.  pushwarden/iocs.json is the single source of truth.
package iocsdata

import _ "embed"

//go:embed iocs.json
var Bundled []byte
