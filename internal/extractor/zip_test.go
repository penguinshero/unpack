package extractor

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildTestZip creates an in-memory zip archive with the given entries
// (name -> content) and returns the raw bytes.
func buildTestZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestZipExtractor_Detect(t *testing.T) {
	ext := &ZipExtractor{}

	valid := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}
	if !ext.Detect(valid) {
		t.Error("expected valid zip magic to be detected")
	}

	invalid := []byte{0x00, 0x00, 0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as zip")
	}

	tooShort := []byte{0x50, 0x4B}
	if ext.Detect(tooShort) {
		t.Error("expected too-short header to not be detected as zip")
	}
}

func TestZipExtractor_ExtractAndList(t *testing.T) {
	ext := &ZipExtractor{}
	dir := t.TempDir()

	entries := map[string]string{
		"hello.txt":        "hello world",
		"nested/inner.txt": "nested content",
	}
	zipBytes := buildTestZip(t, entries)
	srcPath := writeTempFile(t, dir, "test.zip", zipBytes)

	destDir := filepath.Join(dir, "out")
	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for name, expectedContent := range entries {
		gotPath := filepath.Join(destDir, name)
		got, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatalf("failed to read extracted file %s: %v", name, err)
		}
		if string(got) != expectedContent {
			t.Errorf("content mismatch for %s: expected %q, got %q", name, expectedContent, got)
		}
	}

	names, err := ext.List(srcPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(names))
	}
}

// TestZipExtractor_RelativeDestDir ensures extraction works correctly when
// destDir is relative (e.g. "."), not just absolute paths. This guards
// against the absolute-path comparison regression found earlier.
func TestZipExtractor_RelativeDestDir(t *testing.T) {
	ext := &ZipExtractor{}
	dir := t.TempDir()

	entries := map[string]string{"file.txt": "data"}
	zipBytes := buildTestZip(t, entries)
	srcPath := writeTempFile(t, dir, "test.zip", zipBytes)

	// switch working directory to the temp dir, then extract with destDir = "."
	origWd, _ := os.Getwd()
	defer os.Chdir(origWd)

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	if err := ext.Extract(srcPath, "."); err != nil {
		t.Fatalf("extraction with relative destDir failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Fatalf("expected extracted file not found: %v", err)
	}
}

func TestZipExtractor_CorruptFile(t *testing.T) {
	ext := &ZipExtractor{}
	dir := t.TempDir()

	// valid zip magic bytes followed by garbage instead of a real archive
	garbage := append([]byte{0x50, 0x4B, 0x03, 0x04}, []byte("not a real zip body")...)
	srcPath := writeTempFile(t, dir, "corrupt.zip", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt zip, got nil")
	}
}

func TestZipExtractor_EmptyArchive(t *testing.T) {
	ext := &ZipExtractor{}
	dir := t.TempDir()

	zipBytes := buildTestZip(t, map[string]string{})
	srcPath := writeTempFile(t, dir, "empty.zip", zipBytes)

	destDir := filepath.Join(dir, "out")
	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("expected no error extracting empty archive, got: %v", err)
	}

	names, err := ext.List(srcPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 entries in empty archive, got %d", len(names))
	}
}

// TestZipExtractor_ZipSlip verifies that a malicious entry attempting path
// traversal outside destDir is rejected rather than written to disk.
func TestZipExtractor_ZipSlip(t *testing.T) {
	ext := &ZipExtractor{}
	dir := t.TempDir()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("../../evil.txt")
	if err != nil {
		t.Fatalf("failed to create malicious zip entry: %v", err)
	}
	if _, err := f.Write([]byte("malicious content")); err != nil {
		t.Fatalf("failed to write malicious entry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	srcPath := writeTempFile(t, dir, "slip.zip", buf.Bytes())
	destDir := filepath.Join(dir, "safe_out")

	err = ext.Extract(srcPath, destDir)
	if err == nil {
		t.Fatal("expected zip slip attempt to be rejected, got nil error")
	}

	// confirm the malicious file was NOT written outside destDir
	escapedPath := filepath.Join(dir, "evil.txt")
	if _, statErr := os.Stat(escapedPath); statErr == nil {
		t.Fatal("zip slip succeeded: malicious file was written outside destDir")
	}
}
