package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
		fmt.Println("target file:", args[0])
		fmt.Println("output dir:", outputDir)
		// TODO: look up the matching extractor from the registry and run Extract()
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
