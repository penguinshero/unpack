package extractor

// init registers all built-in extractors at package load time
func init() {
	Register(&ZipExtractor{})
	Register(&TarExtractor{})
	Register(&GzExtractor{})
	Register(&Bz2Extractor{})
	Register(&XzExtractor{})
	Register(&ZstExtractor{})
}
