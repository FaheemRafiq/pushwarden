package update

// PublicKeys verify checksums.txt.sig (ed25519, base64). A slice so keys can
// rotate: add the new key, release with it, then drop the old one.
//
// Generate a pair with `go run ./scripts/keygen PATH`; commit only the public
// key here. Until a key is listed, self-update refuses to install anything.
var PublicKeys = []string{
	"Twttq9ERdflw7tFDObUhzP4wFuwrGIqQ/qC9Kk8gtBg=", // 2026-09-28
}
