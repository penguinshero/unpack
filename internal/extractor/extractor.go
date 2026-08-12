package extractor

// Extractor is implemented by every supported archive format.
type Extractor interface {
	// Detect reports whether the given header bytes match this format's magic signature.
	Detect(header []byte) bool

	// Extract unpacks the archive at src into destDir.
	Extract(src, destDir string) error

	// List returns the names of entries inside the archive without extracting them.
	List(src string) ([]string, error)

	// Name returns the format identifier ("zip", "gzip", etc).
	Name() string
}

var registry = make(map[string]Extractor)

// Register adds an extractor to the registry.
func Register(e Extractor) {
	registry[e.Name()] = e
}

// DetectExtractor finds the extractor whose Detect matches the given header bytes.
func DetectExtractor(header []byte) Extractor {
	for _, e := range registry {
		if e.Detect(header) {
			return e
		}
	}
	return nil
}

// Get returns a registered extractor by name.
func Get(name string) (Extractor, bool) {
	e, ok := registry[name]
	return e, ok
}
