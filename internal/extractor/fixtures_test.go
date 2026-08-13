package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

// requireFixture skips the test if the given fixture file doesn't exist in
// testdata/, rather than failing the whole suite when an optional archive
// format's sample file wasn't generated on this machine.
func requireFixture(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("testdata", name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("fixture %s not found, skipping (run testdata generation script first)", name)
	}
	return path
}
