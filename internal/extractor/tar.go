package extractor

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// tarMagicOffset is where the "ustar" identifier lives inside a tar header block
const tarMagicOffset = 257

var gzipMagic = []byte{0x1F, 0x8B}
var bzip2Magic = []byte{0x42, 0x5A, 0x68}
var xzMagic = []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// TarExtractor implements the Extractor interface for plain (uncompressed) tar archives
type TarExtractor struct{}

func (t *TarExtractor) Name() string {
	return "tar"
}

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

func (t *TarExtractor) List(src string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar archive: %w", err)
	}
	defer f.Close()

	return listTarStream(f)
}

// GzExtractor handles gzip-compressed input (both .tar.gz and standalone .gz)
type GzExtractor struct{}

func (g *GzExtractor) Name() string {
	return "gzip"
}

func (g *GzExtractor) Detect(header []byte) bool {
	if len(header) < len(gzipMagic) {
		return false
	}
	return header[0] == gzipMagic[0] && header[1] == gzipMagic[1]
}

func (g *GzExtractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open gzip file: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return extractCompressedStream(gzReader, src, destDir, ".gz")
}

func (g *GzExtractor) List(src string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip file: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return listCompressedStream(gzReader, src, ".gz")
}

// Bz2Extractor handles bzip2-compressed input (both .tar.bz2 and standalone .bz2)
type Bz2Extractor struct{}

func (b *Bz2Extractor) Name() string {
	return "bzip2"
}

func (b *Bz2Extractor) Detect(header []byte) bool {
	if len(header) < len(bzip2Magic) {
		return false
	}
	for i, m := range bzip2Magic {
		if header[i] != m {
			return false
		}
	}
	return true
}

func (b *Bz2Extractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open bzip2 file: %w", err)
	}
	defer f.Close()

	bz2Reader := bzip2.NewReader(f)

	return extractCompressedStream(bz2Reader, src, destDir, ".bz2")
}

func (b *Bz2Extractor) List(src string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open bzip2 file: %w", err)
	}
	defer f.Close()

	bz2Reader := bzip2.NewReader(f)

	return listCompressedStream(bz2Reader, src, ".bz2")
}

// XzExtractor handles xz-compressed input (both .tar.xz and standalone .xz)
type XzExtractor struct{}

func (x *XzExtractor) Name() string {
	return "xz"
}

func (x *XzExtractor) Detect(header []byte) bool {
	if len(header) < len(xzMagic) {
		return false
	}
	for i, m := range xzMagic {
		if header[i] != m {
			return false
		}
	}
	return true
}

func (x *XzExtractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open xz file: %w", err)
	}
	defer f.Close()

	xzReader, err := xz.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create xz reader: %w", err)
	}

	return extractCompressedStream(xzReader, src, destDir, ".xz")
}

func (x *XzExtractor) List(src string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open xz file: %w", err)
	}
	defer f.Close()

	xzReader, err := xz.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create xz reader: %w", err)
	}

	return listCompressedStream(xzReader, src, ".xz")
}

// ZstExtractor handles zstd-compressed input (both .tar.zst and standalone .zst)
type ZstExtractor struct{}

func (z *ZstExtractor) Name() string {
	return "zstd"
}

func (z *ZstExtractor) Detect(header []byte) bool {
	if len(header) < len(zstdMagic) {
		return false
	}
	for i, m := range zstdMagic {
		if header[i] != m {
			return false
		}
	}
	return true
}

func (z *ZstExtractor) Extract(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open zstd file: %w", err)
	}
	defer f.Close()

	zstdReader, err := zstd.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	return extractCompressedStream(zstdReader, src, destDir, ".zst")
}

func (z *ZstExtractor) List(src string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("failed to open zstd file: %w", err)
	}
	defer f.Close()

	zstdReader, err := zstd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	return listCompressedStream(zstdReader, src, ".zst")
}

// extractCompressedStream inspects the decompressed stream: if it looks like a
// tar archive, it extracts entries normally. Otherwise it writes the decompressed
// data as a single plain file (e.g. "notes.txt.gz" -> "notes.txt").
func extractCompressedStream(r io.Reader, originalSrc, destDir, stripExt string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination dir: %w", err)
	}

	buffered := bufio.NewReaderSize(r, 512)

	peek, err := buffered.Peek(tarMagicOffset + 5)
	isTar := err == nil && string(peek[tarMagicOffset:tarMagicOffset+5]) == "ustar"

	if isTar {
		return extractTarStream(buffered, destDir)
	}

	outName := strings.TrimSuffix(filepath.Base(originalSrc), stripExt)
	outPath := filepath.Join(destDir, outName)

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, buffered); err != nil {
		return fmt.Errorf("failed to write decompressed data: %w", err)
	}

	return nil
}

// listCompressedStream mirrors extractCompressedStream's tar-or-plain-file detection,
// but only returns entry names instead of writing to disk.
func listCompressedStream(r io.Reader, originalSrc, stripExt string) ([]string, error) {
	buffered := bufio.NewReaderSize(r, 512)

	peek, err := buffered.Peek(tarMagicOffset + 5)
	isTar := err == nil && string(peek[tarMagicOffset:tarMagicOffset+5]) == "ustar"

	if isTar {
		return listTarStream(buffered)
	}

	outName := strings.TrimSuffix(filepath.Base(originalSrc), stripExt)
	return []string{outName}, nil
}

// extractTarStream reads tar entries from r and writes them to destDir.
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

// listTarStream reads tar entry names from r without writing anything to disk.
func listTarStream(r io.Reader) ([]string, error) {
	tarReader := tar.NewReader(r)
	var names []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry: %w", err)
		}
		names = append(names, header.Name)
	}

	return names, nil
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
		return nil
	}
}
