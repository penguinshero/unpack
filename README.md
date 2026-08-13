# 🔥 unpack

**A universal archive extractor for Linux.**
Detects archive type by file content (magic bytes), not by extension — so it works even on renamed or misnamed files.
![CI](https://github.com/penguinshero/unpack/actions/workflows/ci.yml/badge.svg)

## Supported formats

| Format | Extension(s) | Notes |
|---|---|---|
| ZIP | `.zip` | |
| TAR | `.tar` | |
| GZIP | `.gz`, `.tar.gz`, `.tgz` | Auto-detects plain file vs tar content |
| BZIP2 | `.bz2`, `.tar.bz2` | Auto-detects plain file vs tar content |
| XZ | `.xz`, `.tar.xz` | Auto-detects plain file vs tar content |
| ZSTD | `.zst`, `.tar.zst` | Auto-detects plain file vs tar content |
| 7-Zip | `.7z` | |
| RAR | `.rar` | Requires the `unrar` binary (see below) |

## Installation

### From source

```bash
git clone https://github.com/penguinshero/unpack.git
cd unpack
go build -o unpack ./cmd/unpack
sudo mv unpack /usr/local/bin/
```

### Using `go install`

```bash
go install github.com/penguinshero/unpack/cmd/unpack@latest
```

### RAR support (optional dependency)

RAR extraction shells out to the system `unrar` binary, since no reliable pure-Go RAR implementation exists.

```bash
sudo apt install unrar        # Debian/Ubuntu
sudo pacman -S unrar          # Arch
sudo dnf install unrar        # Fedora
```

If `unrar` is not installed, all other formats still work — you'll only see an error when extracting a `.rar` file.

## Usage

```bash
unpack [file] [flags]
```

### Extract an archive

```bash
unpack archive.zip
```

Extracts into the current directory by default.

### Extract to a specific directory

```bash
unpack archive.tar.gz -o /path/to/output
```

### Preview contents without extracting

```bash
unpack archive.7z -l
```

### Verbose output

```bash
unpack archive.rar -o ./out -v
```

### Flags

| Flag | Shorthand | Description |
|---|---|---|
| `--output` | `-o` | Output directory for extracted files (default: `.`) |
| `--list` | `-l` | List archive contents without extracting |
| `--verbose` | `-v` | Show detected format and extra detail |
| `--help` | `-h` | Show help |

## How it works

Instead of trusting the file extension, `unpack` reads the first bytes of the file and matches them against known magic signatures for each format. This means a `.zip` file renamed to `.txt`, or any archive with no extension at all, still gets detected and extracted correctly.

For compressed streams (gzip, bzip2, xz, zstd), `unpack` also inspects the decompressed content: if it looks like a tar archive, it extracts the full archive structure; otherwise it treats it as a single compressed file and writes out the decompressed result.

## Security

- **Zip slip / tar slip protection** — archive entries containing path traversal sequences (`../`) are rejected before writing to disk, preventing extraction outside the target directory.

## Roadmap

- [ ] Password-protected archive support
- [ ] Progress bar for large extractions
- [ ] Archive metadata / inspection mode

## License

MIT — see [LICENSE](LICENSE)
