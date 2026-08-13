package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHeader_ExactSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte{0x50, 0x4B, 0x03, 0x04, 0xAA, 0xBB}

	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	header, err := ReadHeader(path, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(header) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(header))
	}
	for i, b := range []byte{0x50, 0x4B, 0x03, 0x04} {
		if header[i] != b {
			t.Errorf("byte %d: expected %X, got %X", i, b, header[i])
		}
	}
}

// TestReadHeader_ShorterThanRequested ensures files smaller than the requested
// header size don't cause an error, and just return what's available.
func TestReadHeader_ShorterThanRequested(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.bin")
	content := []byte{0x01, 0x02}

	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	header, err := ReadHeader(path, 265)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(header) != 2 {
		t.Fatalf("expected 2 bytes for short file, got %d", len(header))
	}
}

func TestReadHeader_NonexistentFile(t *testing.T) {
	_, err := ReadHeader("/nonexistent/path/does-not-exist.zip", 4)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// TestReadHeader_TarSizedFile verifies a header long enough to reach the
// tar "ustar" magic offset (257) can be read correctly from a larger file.
func TestReadHeader_TarSizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tarlike.bin")

	content := make([]byte, 512)
	copy(content[257:], []byte("ustar"))

	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	header, err := ReadHeader(path, 265)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(header[257:262]) != "ustar" {
		t.Fatalf("expected ustar magic at offset 257, got %q", header[257:262])
	}
}
