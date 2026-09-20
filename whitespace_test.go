// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package bip39

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The English BIP-39 test vector for entropy 0x7f7f..., used here in
// preference to the all-"abandon" vector because every word is distinct. A
// tokenizer that emits a spurious empty word cannot then land on the right
// entropy by accident: the empty string resolves to word index 0, which the
// all-"abandon" sentence is made of.
const (
	whitespaceVectorMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	whitespaceVectorEntropy  = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
)

// TestMnemonicWhitespaceTolerance pins the tokenization contract: words are
// separated by runs of whitespace, not by exactly one ASCII space. Mnemonics
// reach this library from clipboards, text fields, and files, so a doubled
// space, a tab, or a trailing newline is an ordinary input rather than a
// corrupt one, and each of these sentences names the same twelve words.
// Splitting the sentence on a single space instead rejects every case below.
func TestMnemonicWhitespaceTolerance(t *testing.T) {
	want, err := hex.DecodeString(whitespaceVectorEntropy)
	assertNil(t, err)

	for _, testCase := range []struct {
		name     string
		mnemonic string
	}{
		{"canonical", whitespaceVectorMnemonic},
		{
			"doubled space",
			strings.Replace(whitespaceVectorMnemonic, " ", "  ", 1),
		},
		{
			"tab separator",
			strings.Replace(whitespaceVectorMnemonic, " ", "\t", 1),
		},
		{
			"newline separator",
			strings.Replace(whitespaceVectorMnemonic, " ", "\n", 1),
		},
		{"leading space", " " + whitespaceVectorMnemonic},
		{"trailing newline", whitespaceVectorMnemonic + "\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertTrue(t, IsMnemonicValid(testCase.mnemonic))

			entropy, err := EntropyFromMnemonic(testCase.mnemonic)
			assertNil(t, err)
			assertEqualByteSlices(t, want, entropy)
		})
	}
}

// TestMnemonicWhitespaceToleranceIsBounded keeps the tolerance above from
// degenerating into acceptance. Whitespace between words is ignored; nothing
// else about the sentence is.
func TestMnemonicWhitespaceToleranceIsBounded(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		mnemonic string
	}{
		{"empty", ""},
		{"whitespace only", " \t\n "},
		{
			"word dropped",
			strings.TrimSuffix(whitespaceVectorMnemonic, " yellow"),
		},
		{
			"word misspelled",
			strings.Replace(whitespaceVectorMnemonic, "yellow", "yellwo", 1),
		},
		{
			"whitespace inside a word",
			strings.Replace(whitespaceVectorMnemonic, "sausage", "saus age", 1),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertFalse(t, IsMnemonicValid(testCase.mnemonic))

			_, err := EntropyFromMnemonic(testCase.mnemonic)
			assertNotNil(t, err)
		})
	}
}
