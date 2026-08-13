package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXzExtractor_Detect(t *testing.T) {
	ext := &XzExtractor{}

	valid := []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}
	if !ext.Detect(valid) {
		t.Error("expected valid xz magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as xz")
	}
}

func TestXzExtractor_ExtractPlainFile(t *testing.T) {
	ext := &XzExtractor{}
	srcPath := requireFixture(t, "sample.xz")

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

func TestXzExtractor_CorruptFile(t *testing.T) {
	ext := &XzExtractor{}
	dir := t.TempDir()

	garbage := append([]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, []byte("not real xz data")...)
	srcPath := writeTempFile(t, dir, "corrupt.xz", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt xz, got nil")
	}
}
