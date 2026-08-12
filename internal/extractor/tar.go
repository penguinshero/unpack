package extractor

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tarMagicOffset is where the "ustar" identifier lives inside a tar header block
const tarMagicOffset = 257

// gzipMagic is the signature bytes at the start of a gzip-compressed file
var gzipMagic = []byte{0x1F, 0x8B}

// TarExtractor implements the Extractor interface for plain (uncompressed) tar archives
type TarExtractor struct{}

func (t *TarExtractor) Name() string {
	return "tar"
}

// Detect checks for the "ustar" magic string at its fixed offset in the tar header
func (t *TarExtractor) Detect(header []byte) bool {
	if len(header) < tarMagicOffset+5 {
		return false
	}
	return string(header[tarMagicOffset:tarMagicOffset+5]) == "ustar"
}

func (t *TarExtractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open tar archive: %w", err)
	}
	defer f.Close()

	return extractTarStream(f, destDir)
}

// TarGzExtractor implements the Extractor interface for gzip-compressed tar archives (.tar.gz)
type TarGzExtractor struct{}

func (t *TarGzExtractor) Name() string {
	return "tar.gz"
}

// Detect checks for the gzip magic signature. Note: this is also true for plain .gz files,
// but since unpack works on archives, we treat gzip streams as tar.gz candidates.
func (t *TarGzExtractor) Detect(header []byte) bool {
	if len(header) < len(gzipMagic) {
		return false
	}
	return header[0] == gzipMagic[0] && header[1] == gzipMagic[1]
}

func (t *TarGzExtractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open tar.gz archive: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return extractTarStream(gzReader, destDir)
}

// extractTarStream reads tar entries from r and writes them to destDir.
// Shared by both plain tar and tar.gz extraction paths.
func extractTarStream(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination dir: %w", err)
	}

	tarReader := tar.NewReader(r)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if err := extractTarEntry(header, tarReader, destDir); err != nil {
			return fmt.Errorf("failed to extract %s: %w", header.Name, err)
		}
	}

	return nil
}

// extractTarEntry writes a single entry from the tar stream to disk.
// It guards against path traversal (tar slip) via "../" in entry names.
func extractTarEntry(header *tar.Header, tarReader *tar.Reader, destDir string) error {
	targetPath := filepath.Join(destDir, header.Name)

	if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path (tar slip attempt): %s", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(targetPath, os.FileMode(header.Mode))

	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, tarReader)
		return err

	default:
		// symlinks, devices, etc. are skipped for now
		return nil
	}
}
