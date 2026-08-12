package detect

import (
	"io"
	"os"
)

// ReadHeader reads up to n bytes from the start of the file at path.
// It uses io.ReadFull so partial/short reads don't silently truncate
// the header used for magic-byte detection.
func ReadHeader(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:read], nil
}
