package extractor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"archive/zip"
)

// zipMagic is the signature bytes found at the start of every zip file
var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04}

// ZipExtractor implements the Extractor interface for standard zip archives
type ZipExtractor struct{}

// Name returns the identifier used to register and look up this extractor
func (z *ZipExtractor) Name() string {
	return "zip"
}

// Detect checks whether the given header bytes match the zip magic signature
func (z *ZipExtractor) Detect(header []byte) bool {
	if len(header) < len(zipMagic) {
		return false
	}
	for i, b := range zipMagic {
		if header[i] != b {
			return false
		}
	}
	return true
}

// Extract unpacks the zip archive at src into destDir
func (z *ZipExtractor) Extract(src, destDir string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer reader.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination dir: %w", err)
	}

	for _, file := range reader.File {
		if err := extractZipEntry(file, destDir); err != nil {
			return fmt.Errorf("failed to extract %s: %w", file.Name, err)
		}
	}

	return nil
}

// extractZipEntry writes a single file/directory entry from the zip archive to disk.
// It guards against zip slip (path traversal via "../" in entry names).
func extractZipEntry(file *zip.File, destDir string) error {
	targetPath := filepath.Join(destDir, file.Name)

	// zip slip protection: resolved path must stay inside destDir
	if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path (zip slip attempt): %s", file.Name)
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
