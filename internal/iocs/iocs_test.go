package iocs

import "testing"

func TestBundledCompilesWithRE2(t *testing.T) {
	i, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`global['_V']='8-st17'`, `global['!']='A10-010'`, `global["_V"] = "9-10094"`} {
		if !i.Marker.MatchString(s) {
			t.Errorf("marker should match %s", s)
		}
	}
	if i.Marker.MatchString("const globalThis = {}; module.exports = {}") {
		t.Error("false positive")
	}
	if !i.IsFontName("fa-solid-900.woff2") {
		t.Error("fa-solid-900 missing")
	}
}
