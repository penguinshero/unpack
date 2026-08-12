package detect

import (
	"io"
	"os"
)

// ReadHeader ফাইলের প্রথম n বাইট পড়ে return করে magic-byte detection এর জন্য
func ReadHeader(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:read], nil
}
