# go-bip39

A Go implementation of the [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) specification for mnemonic seed phrases used in cryptocurrency wallet key derivation.

## Overview

This library provides functionality for:
- Generating random entropy for mnemonic creation
- Converting entropy to mnemonic word sequences
- Converting mnemonics back to entropy
- Generating binary seeds from mnemonics using PBKDF2
- Validating mnemonic phrases
- Support for multiple languages (English, Chinese Simplified, Chinese Traditional, Czech, French, Italian, Japanese, Korean, Spanish)

## Installation

```bash
go get github.com/blinklabs-io/go-bip39
```

## Usage

```go
package main

import (
    "encoding/hex"
    "fmt"

    "github.com/blinklabs-io/go-bip39"
)

func main() {
    // Generate 256 bits of entropy
    entropy, _ := bip39.NewEntropy(256)

    // Generate a mnemonic from the entropy
    mnemonic, _ := bip39.NewMnemonic(entropy)
    fmt.Println("Mnemonic:", mnemonic)

    // Generate a seed from the mnemonic with a password
    seed := bip39.NewSeed(mnemonic, "password")
    fmt.Println("Seed:", hex.EncodeToString(seed))

    // Validate a mnemonic
    valid := bip39.IsMnemonicValid(mnemonic)
    fmt.Println("Valid:", valid)
}
```

## Credits

This library is a revival of the original [tyler-smith/go-bip39](https://github.com/tyler-smith/go-bip39) library, which is no longer available. We thank Tyler Smith for his original work on this implementation.

## License

MIT License - see [LICENSE](LICENSE) for details.

Original work Copyright (c) 2014-2018 Tyler Smith and contributors
Modified work Copyright (c) 2026 Blink Labs Software
