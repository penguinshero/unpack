package extractor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bodgit/sevenzip"
)

// sevenZipMagic is the signature bytes at the start of a 7z archive
var sevenZipMagic = []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}

// SevenZipExtractor implements the Extractor interface for 7z archives
type SevenZipExtractor struct{}

func (s *SevenZipExtractor) Name() string {
	return "7z"
}

// Detect checks for the 7z magic signature
func (s *SevenZipExtractor) Detect(header []byte) bool {
	if len(header) < len(sevenZipMagic) {
		return false
	}
	for i, b := range sevenZipMagic {
		if header[i] != b {
			return false
		}
	}
	return true
}

// Extract unpacks the 7z archive at src into destDir
func (s *SevenZipExtractor) Extract(src, destDir string) error {
	reader, err := sevenzip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open 7z archive: %w", err)
	}
	defer reader.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination dir: %w", err)
	}

	for _, file := range reader.File {
		if err := extractSevenZipEntry(file, destDir); err != nil {
			return fmt.Errorf("failed to extract %s: %w", file.Name, err)
		}
	}

	return nil
}

// List returns the names of all entries in the 7z archive without extracting them
func (s *SevenZipExtractor) List(src string) ([]string, error) {
	reader, err := sevenzip.OpenReader(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open 7z archive: %w", err)
	}
	defer reader.Close()

	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	return names, nil
}

// extractSevenZipEntry writes a single file/directory entry from the 7z archive to disk.
// It guards against path traversal (7z slip) via "../" in entry names.
func extractSevenZipEntry(file *sevenzip.File, destDir string) error {
	targetPath := filepath.Join(destDir, file.Name)

	if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path (7z slip attempt): %s", file.Name)
	}

	if file.FileInfo().IsDir() {
		return os.MkdirAll(targetPath, file.Mode())
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}

	srcFile, err := file.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
