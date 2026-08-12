package extractor

// init registers all built-in extractors at package load time
func init() {
	Register(&ZipExtractor{})
	Register(&TarExtractor{})
	Register(&TarGzExtractor{})
	Register(&TarBz2Extractor{})
	Register(&TarXzExtractor{})
	Register(&TarZstExtractor{})
}
