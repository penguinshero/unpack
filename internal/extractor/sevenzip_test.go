package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSevenZipExtractor_Detect(t *testing.T) {
	ext := &SevenZipExtractor{}

	valid := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
	if !ext.Detect(valid) {
		t.Error("expected valid 7z magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as 7z")
	}
}

func TestSevenZipExtractor_ExtractAndList(t *testing.T) {
	ext := &SevenZipExtractor{}
	srcPath := requireFixture(t, "sample.7z")

	dir := t.TempDir()
	destDir := filepath.Join(dir, "out")

	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "sample.txt"))
	if err != nil {
		t.Fatalf("expected output file not found: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty extracted content")
	}

	names, err := ext.List(srcPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) == 0 {
		t.Error("expected at least one entry in list output")
	}
}

func TestSevenZipExtractor_CorruptFile(t *testing.T) {
	ext := &SevenZipExtractor{}
	dir := t.TempDir()

	garbage := append([]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, []byte("not real 7z data")...)
	srcPath := writeTempFile(t, dir, "corrupt.7z", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt 7z, got nil")
	}
}
