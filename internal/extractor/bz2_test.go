package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBz2Extractor_Detect(t *testing.T) {
	ext := &Bz2Extractor{}

	valid := []byte{0x42, 0x5A, 0x68, 0x39}
	if !ext.Detect(valid) {
		t.Error("expected valid bzip2 magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as bzip2")
	}
}

func TestBz2Extractor_ExtractPlainFile(t *testing.T) {
	ext := &Bz2Extractor{}
	srcPath := requireFixture(t, "sample.bz2")

	dir := t.TempDir()
	destDir := filepath.Join(dir, "out")

	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "sample"))
	if err != nil {
		t.Fatalf("expected output file not found: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty extracted content")
	}
}

func TestBz2Extractor_CorruptFile(t *testing.T) {
	ext := &Bz2Extractor{}
	dir := t.TempDir()

	garbage := append([]byte{0x42, 0x5A, 0x68, 0x39}, []byte("not real bzip2 data")...)
	srcPath := writeTempFile(t, dir, "corrupt.bz2", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt bzip2, got nil")
	}
}
