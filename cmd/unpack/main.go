package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/penguinshero/unpack/internal/detect"
	"github.com/penguinshero/unpack/internal/extractor"
)

// banner is shown in the help/usage output
const banner = `🔥 unpack
universal extractor for linux
`

var (
	outputDir string
	verbose   bool
)

// rootCmd is the base command executed when no subcommand is given
var rootCmd = &cobra.Command{
	Use:   "unpack [file]",
	Short: "universal extractor for linux",
	Long:  banner + "\nDetects archive type by file content (magic bytes), not extension, and extracts it.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		src := args[0]

		header, err := detect.ReadHeader(src, 265)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error reading file:", err)
			os.Exit(1)
		}

		ext := extractor.DetectExtractor(header)
		if ext == nil {
			fmt.Fprintln(os.Stderr, "unsupported or unrecognized archive format")
			os.Exit(1)
		}

		if verbose {
			fmt.Printf("detected format: %s\n", ext.Name())
		}

		if err := ext.Extract(src, outputDir); err != nil {
			fmt.Fprintln(os.Stderr, "extraction failed:", err)
			os.Exit(1)
		}

		fmt.Println("extracted successfully to:", outputDir)
	},
}

func init() {
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", ".", "output directory for extracted files")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
