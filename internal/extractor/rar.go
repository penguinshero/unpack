package extractor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// rarMagic covers both RAR4 ("Rar!\x1A\x07\x00") and RAR5 ("Rar!\x1A\x07\x01\x00") signatures.
// We only need the first 6 bytes, which are common to both versions.
var rarMagic = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}

// RarExtractor implements the Extractor interface for RAR archives by shelling
// out to the system's "unrar" binary, since no reliable pure-Go RAR writer/extractor exists.
type RarExtractor struct{}

func (r *RarExtractor) Name() string {
	return "rar"
}

// Detect checks for the RAR magic signature (first 6 bytes, shared by RAR4 and RAR5)
func (r *RarExtractor) Detect(header []byte) bool {
	if len(header) < len(rarMagic) {
		return false
	}
	for i, b := range rarMagic {
		if header[i] != b {
			return false
		}
	}
	return true
}

// Extract unpacks the RAR archive at src into destDir using the external unrar binary.
func (r *RarExtractor) Extract(src, destDir string) error {
	if err := checkUnrarInstalled(); err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination dir: %w", err)
	}

	// "x" preserves the archive's internal directory structure (unlike "e")
	// "-y" auto-confirms any prompts (overwrite, etc)
	cmd := exec.Command("unrar", "x", "-y", src, destDir+"/")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unrar extraction failed: %s", strings.TrimSpace(stderr.String()))
	}

	return nil
}

// List returns the names of entries inside the RAR archive without extracting them,
// using "unrar lb" (bare listing mode: one filename per line).
func (r *RarExtractor) List(src string) ([]string, error) {
	if err := checkUnrarInstalled(); err != nil {
		return nil, err
	}

	cmd := exec.Command("unrar", "lb", src)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("unrar listing failed: %s", strings.TrimSpace(stderr.String()))
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// checkUnrarInstalled verifies the "unrar" binary is available on PATH,
// returning a clear, actionable error if it's missing.
func checkUnrarInstalled() error {
	if _, err := exec.LookPath("unrar"); err != nil {
		return fmt.Errorf("rar support requires the 'unrar' binary, but it was not found on PATH.\ninstall it with: sudo apt install unrar")
	}
	return nil
}
