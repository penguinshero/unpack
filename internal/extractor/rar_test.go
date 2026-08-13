package extractor

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRarExtractor_Detect(t *testing.T) {
	ext := &RarExtractor{}

	valid := []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}
	if !ext.Detect(valid) {
		t.Error("expected valid RAR magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as RAR")
	}
}

// TestRarExtractor_ExtractAndList only runs if both the "unrar" binary and the
// sample.rar fixture are available, since RAR support depends on an external tool.
func TestRarExtractor_ExtractAndList(t *testing.T) {
	if _, err := exec.LookPath("unrar"); err != nil {
		t.Skip("unrar binary not found on PATH, skipping RAR extraction test")
	}

	ext := &RarExtractor{}
	srcPath := requireFixture(t, "sample.rar")

	dir := t.TempDir()
	destDir := filepath.Join(dir, "out")

	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	names, err := ext.List(srcPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) == 0 {
		t.Error("expected at least one entry in list output")
	}
}
