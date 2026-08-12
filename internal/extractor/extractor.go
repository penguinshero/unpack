package extractor

// Extractor প্রতিটা archive format কে এই interface implement করতে হবে
type Extractor interface {
	// Detect ফাইলের প্রথম কয়েক বাইট (magic bytes) দেখে বলবে এই format কিনা
	Detect(header []byte) bool

	// Extract src ফাইলকে destDir এ extract করবে
	Extract(src, destDir string) error

	// Name format এর identifier ("zip", "tar.gz" ইত্যাদি)
	Name() string
}

var registry = make(map[string]Extractor)

// Register নতুন extractor কে registry তে যোগ করে
func Register(e Extractor) {
	registry[e.Name()] = e
}

// Detect header বাইট দিয়ে সঠিক extractor খুঁজে বের করে
func DetectExtractor(header []byte) Extractor {
	for _, e := range registry {
		if e.Detect(header) {
			return e
		}
	}
	return nil
}

// Get নাম দিয়ে নির্দিষ্ট extractor return করে
func Get(name string) (Extractor, bool) {
	e, ok := registry[name]
	return e, ok
}
