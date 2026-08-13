package extractor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// buildTestTar creates an in-memory tar archive with the given entries.
func buildTestTar(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)

	for name, content := range entries {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content for %s: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	return buf.Bytes()
}

// buildTestTarGz wraps buildTestTar output in gzip compression.
func buildTestTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	tarBytes := buildTestTar(t, entries)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(tarBytes); err != nil {
		t.Fatalf("failed to write gzip data: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	return buf.Bytes()
}

func TestTarExtractor_Detect(t *testing.T) {
	ext := &TarExtractor{}

	header := make([]byte, 512)
	copy(header[257:], []byte("ustar"))

	if !ext.Detect(header) {
		t.Error("expected valid tar magic to be detected")
	}

	invalid := make([]byte, 300)
	if ext.Detect(invalid) {
		t.Error("expected non-tar header to not be detected")
	}
}

func TestTarExtractor_ExtractAndList(t *testing.T) {
	ext := &TarExtractor{}
	dir := t.TempDir()

	entries := map[string]string{
		"hello.txt":        "hello world",
		"nested/inner.txt": "nested content",
	}
	tarBytes := buildTestTar(t, entries)
	srcPath := writeTempFile(t, dir, "test.tar", tarBytes)

	destDir := filepath.Join(dir, "out")
	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for name, expectedContent := range entries {
		got, err := os.ReadFile(filepath.Join(destDir, name))
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

func TestTarExtractor_RelativeDestDir(t *testing.T) {
	ext := &TarExtractor{}
	dir := t.TempDir()

	tarBytes := buildTestTar(t, map[string]string{"file.txt": "data"})
	srcPath := writeTempFile(t, dir, "test.tar", tarBytes)

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

// TestTarExtractor_CorruptFile verifies that a file with valid tar magic bytes
// but garbage/malformed header data after that point fails to extract cleanly.
func TestTarExtractor_CorruptFile(t *testing.T) {
	ext := &TarExtractor{}
	dir := t.TempDir()

	// build a buffer that has "ustar" at the correct offset (so Detect() matches)
	// but the rest of the header block is garbage, which the tar reader must reject.
	garbage := make([]byte, 512)
	copy(garbage[257:], []byte("ustar"))
	for i := 0; i < 256; i++ {
		garbage[i] = 0xFF
	}

	srcPath := writeTempFile(t, dir, "corrupt.tar", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt tar header, got nil")
	}
}


func TestTarExtractor_EmptyArchive(t *testing.T) {
	ext := &TarExtractor{}
	dir := t.TempDir()

	tarBytes := buildTestTar(t, map[string]string{})
	srcPath := writeTempFile(t, dir, "empty.tar", tarBytes)

	destDir := filepath.Join(dir, "out")
	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("expected no error extracting empty tar, got: %v", err)
	}

	names, err := ext.List(srcPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(names))
	}
}

// TestTarExtractor_TarSlip verifies malicious "../" entries are rejected.
func TestTarExtractor_TarSlip(t *testing.T) {
	ext := &TarExtractor{}
	dir := t.TempDir()

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	content := "malicious content"
	hdr := &tar.Header{
		Name: "../../evil.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	}
	if err := w.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write malicious tar header: %v", err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write malicious content: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	srcPath := writeTempFile(t, dir, "slip.tar", buf.Bytes())
	destDir := filepath.Join(dir, "safe_out")

	err := ext.Extract(srcPath, destDir)
	if err == nil {
		t.Fatal("expected tar slip attempt to be rejected, got nil error")
	}

	escapedPath := filepath.Join(dir, "evil.txt")
	if _, statErr := os.Stat(escapedPath); statErr == nil {
		t.Fatal("tar slip succeeded: malicious file was written outside destDir")
	}
}

func TestGzExtractor_Detect(t *testing.T) {
	ext := &GzExtractor{}

	valid := []byte{0x1F, 0x8B, 0x08, 0x00}
	if !ext.Detect(valid) {
		t.Error("expected valid gzip magic to be detected")
	}

	invalid := []byte{0x00, 0x00}
	if ext.Detect(invalid) {
		t.Error("expected invalid magic to not be detected as gzip")
	}
}

// TestGzExtractor_TarContent verifies a .tar.gz stream is extracted as a full
// tar archive (not written as a single opaque file).
func TestGzExtractor_TarContent(t *testing.T) {
	ext := &GzExtractor{}
	dir := t.TempDir()

	entries := map[string]string{"a.txt": "content a", "b.txt": "content b"}
	gzBytes := buildTestTarGz(t, entries)
	srcPath := writeTempFile(t, dir, "test.tar.gz", gzBytes)

	destDir := filepath.Join(dir, "out")
	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for name, expected := range entries {
		got, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		if string(got) != expected {
			t.Errorf("content mismatch for %s: expected %q, got %q", name, expected, got)
		}
	}
}

// TestGzExtractor_PlainFileContent verifies a standalone (non-tar) gzip stream
// is decompressed into a single plain file with the ".gz" suffix stripped.
func TestGzExtractor_PlainFileContent(t *testing.T) {
	ext := &GzExtractor{}
	dir := t.TempDir()

	plainContent := "just a plain text file, not a tar archive"

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(plainContent)); err != nil {
		t.Fatalf("failed to write gzip content: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	srcPath := writeTempFile(t, dir, "notes.txt.gz", buf.Bytes())
	destDir := filepath.Join(dir, "out")

	if err := ext.Extract(srcPath, destDir); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "notes.txt"))
	if err != nil {
		t.Fatalf("expected plain output file not found: %v", err)
	}
	if string(got) != plainContent {
		t.Errorf("content mismatch: expected %q, got %q", plainContent, got)
	}
}

func TestGzExtractor_CorruptFile(t *testing.T) {
	ext := &GzExtractor{}
	dir := t.TempDir()

	garbage := append([]byte{0x1F, 0x8B, 0x08, 0x00}, []byte("not real gzip data")...)
	srcPath := writeTempFile(t, dir, "corrupt.gz", garbage)

	err := ext.Extract(srcPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error extracting corrupt gzip, got nil")
	}
}
