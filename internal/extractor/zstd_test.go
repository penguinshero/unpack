package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZstExtractor_Detect(t *testing.T) {
	ext := &ZstExtractor{}

	valid := []byte{0x28, 0xB5, 0x2F, 0xFD}
	if !ext.Detect(valid) {
		t.Error("expected valid zstd magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as zstd")
	}
}

func TestZstExtractor_ExtractPlainFile(t *testing.T) {
	ext := &ZstExtractor{}
	srcPath := requireFixture(t, "sample.zst")

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

func TestZstExtractor_CorruptFile(t *testing.T) {
	ext := &ZstExtractor{}
	dir := t.TempDir()

	garbage := append([]byte{0x28, 0xB5, 0x2F, 0xFD}, []byte("not real zstd data")...)
	srcPath := writeTempFile(t, dir, "corrupt.zst", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt zstd, got nil")
	}
}
