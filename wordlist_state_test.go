// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package bip39

import (
	"strings"
	"testing"

	"github.com/blinklabs-io/go-bip39/wordlists"
)

// TestSetWordListReplacesReverseIndex covers the state SetWordList owns.
// wordList and wordMap are package-level and must describe one word list at a
// time: a SetWordList that installed the new list without discarding the
// previous reverse index would leave every earlier list's words resolving, so
// a program switched to Spanish would still accept an English mnemonic and
// decode it with the index the English list gave it.
//
// Not parallel: SetWordList replaces package state every other test reads.
func TestSetWordListReplacesReverseIndex(t *testing.T) {
	t.Cleanup(func() { SetWordList(wordlists.English) })

	spanishWords := make(map[string]struct{}, len(wordlists.Spanish))
	for _, word := range wordlists.Spanish {
		spanishWords[word] = struct{}{}
	}
	for _, word := range strings.Fields(whitespaceVectorMnemonic) {
		if _, shared := spanishWords[word]; shared {
			t.Fatalf(
				"word %q appears in both word lists, so it cannot show "+
					"which list is in effect",
				word,
			)
		}
	}

	// English is installed by init, so the English sentence resolves now.
	assertTrue(t, IsMnemonicValid(whitespaceVectorMnemonic))

	SetWordList(wordlists.Spanish)

	for expectedIdx, word := range wordlists.Spanish {
		actualIdx, ok := GetWordIndex(word)
		assertTrue(t, ok)
		assertEqual(t, actualIdx, expectedIdx)
	}
	for _, word := range strings.Fields(whitespaceVectorMnemonic) {
		if actualIdx, ok := GetWordIndex(word); ok {
			t.Errorf(
				"word %q from the replaced list still resolves to index %d",
				word,
				actualIdx,
			)
		}
	}
	assertFalse(t, IsMnemonicValid(whitespaceVectorMnemonic))
	_, err := EntropyFromMnemonic(whitespaceVectorMnemonic)
	assertNotNil(t, err)

	// A sentence in the list now in effect round-trips, so the rejection
	// above is about which list is loaded and not a wedged package.
	entropy := make([]byte, 16)
	spanishMnemonic, err := NewMnemonic(entropy)
	assertNil(t, err)
	assertTrue(t, IsMnemonicValid(spanishMnemonic))
	decoded, err := EntropyFromMnemonic(spanishMnemonic)
	assertNil(t, err)
	assertEqualByteSlices(t, entropy, decoded)

	SetWordList(wordlists.English)

	assertTrue(t, IsMnemonicValid(whitespaceVectorMnemonic))
	assertFalse(t, IsMnemonicValid(spanishMnemonic))
}

// TestSetWordListIgnoresNil covers SetWordList's only guard: a nil list leaves
// the installed list and its reverse index untouched rather than emptying
// both, which would reject every mnemonic.
//
// Not parallel: SetWordList replaces package state every other test reads.
func TestSetWordListIgnoresNil(t *testing.T) {
	t.Cleanup(func() { SetWordList(wordlists.English) })

	SetWordList(nil)

	assertEqualStringSlices(t, wordlists.English, GetWordList())
	// BIP-39 fixes the English list, so "abandon" is its index 0.
	idx, ok := GetWordIndex("abandon")
	assertTrue(t, ok)
	assertEqual(t, idx, 0)
	assertTrue(t, IsMnemonicValid(whitespaceVectorMnemonic))
}
