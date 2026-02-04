# AGENTS.md

This file provides guidance for AI coding agents when working with this repository.

## Project Overview

go-bip39 is a BIP-0039 implementation in Go for generating and validating mnemonic seed phrases used in cryptocurrency wallet key derivation. It is a drop-in replacement for tyler-smith/go-bip39 with the same API.

## Development Commands

```bash
# Run all tests
go test ./...

# Run a specific test
go test -run TestFunctionName ./...

# Run tests with coverage
go test -cover ./...

# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Build
go build ./...
```

## Architecture Notes

This library implements the BIP-0039 standard which defines:
- Mnemonic code generation from entropy
- Conversion of mnemonic to binary seed using PBKDF2
- Word lists for multiple languages (English, Chinese Simplified, Chinese Traditional, Czech, French, Italian, Japanese, Korean, Spanish)

## Key Files

- `bip39.go` - Core implementation of mnemonic generation and seed derivation
- `bip39_test.go` - Test suite including BIP-39 test vectors
- `wordlists/*.go` - Language-specific word lists with CRC32 checksums

## Testing

The BIP-39 test vectors for validation are at: https://github.com/trezor/python-mnemonic/blob/master/vectors.json

Always run `go test ./...` before committing changes to ensure all tests pass.

## Code Style

- Follow standard Go conventions
- Use `go fmt` before committing
- Run `go vet` to catch common issues
- Keep the API compatible with the original tyler-smith/go-bip39 library

## Security Considerations

This library handles cryptographic operations for wallet seed generation. When making changes:
- Do not modify the entropy generation or PBKDF2 derivation without careful review
- Do not alter the word lists (they are standardized by BIP-39)
- Ensure all changes maintain compatibility with the BIP-39 specification
