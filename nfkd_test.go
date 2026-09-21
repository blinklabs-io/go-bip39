// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package bip39

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/blinklabs-io/go-bip39/wordlists"
	"golang.org/x/crypto/pbkdf2"
)

// japaneseVector is one published Japanese BIP-39 test vector. The mnemonics
// separate words with the ideographic space U+3000 and the passphrase is built
// from characters whose NFKD form differs from the form they are written in, so
// the seeds are reproducible only when BIP-39's mandated NFKD normalization is
// applied to both the mnemonic sentence and the passphrase before PBKDF2.
type japaneseVector struct {
	Entropy    string `json:"entropy"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
	Seed       string `json:"seed"`
}

// loadBIP32JPVectors returns the Japanese vectors that BIP-39 itself links as
// the Japanese wordlist test vectors, pinned verbatim from
// https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
func loadBIP32JPVectors(t *testing.T) []japaneseVector {
	t.Helper()
	data, err := os.ReadFile("testdata/test_JP_BIP39.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var vectors []japaneseVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decoding vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vectors
}

// loadTrezorJapaneseVectors returns the "japanese" entry of the Trezor
// reference suite's vectors.json, pinned from
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
// Each entry is [entropy, mnemonic, seed, xprv] and uses the passphrase
// "TREZOR", so unlike the bip32JP set only the mnemonic exercises NFKD.
func loadTrezorJapaneseVectors(t *testing.T) []japaneseVector {
	t.Helper()
	data, err := os.ReadFile("testdata/trezor_vectors_japanese.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var raw [][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decoding vectors: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("no vectors loaded")
	}
	vectors := make([]japaneseVector, 0, len(raw))
	for _, entry := range raw {
		if len(entry) < 3 {
			t.Fatalf("malformed vector entry: %v", entry)
		}
		vectors = append(vectors, japaneseVector{
			Entropy:    entry[0],
			Mnemonic:   entry[1],
			Passphrase: "TREZOR",
			Seed:       entry[2],
		})
	}
	return vectors
}

func TestNewSeedBIP32JPJapaneseVectors(t *testing.T) {
	t.Parallel()
	for _, v := range loadBIP32JPVectors(t) {
		seed := hex.EncodeToString(NewSeed(v.Mnemonic, v.Passphrase))
		if seed != v.Seed {
			t.Errorf(
				"seed mismatch for entropy %s: got %s, want %s",
				v.Entropy,
				seed,
				v.Seed,
			)
		}
	}
}

func TestNewSeedTrezorJapaneseVectors(t *testing.T) {
	t.Parallel()
	for _, v := range loadTrezorJapaneseVectors(t) {
		seed := hex.EncodeToString(NewSeed(v.Mnemonic, v.Passphrase))
		if seed != v.Seed {
			t.Errorf(
				"seed mismatch for entropy %s: got %s, want %s",
				v.Entropy,
				seed,
				v.Seed,
			)
		}
	}
}

// TestNewSeedASCIIUnchanged pins the compatibility half of the contract: NFKD
// is the identity on ASCII, so no already-derived ASCII seed may move. The
// expected value is the pre-normalization derivation, recomputed here rather
// than read from NewSeed.
func TestNewSeedASCIIUnchanged(t *testing.T) {
	t.Parallel()
	mnemonics := []string{
		"",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n",
		" leading and trailing ",
		"!\"#$%&'()*+,-./0123456789:;<=>?@ABCXYZ[\\]^_`abcxyz{|}~",
	}
	passwords := []string{"", "TREZOR", "  ", "p@ssw0rd\t\n", "~!?"}
	for _, mnemonic := range mnemonics {
		for _, password := range passwords {
			want := pbkdf2.Key(
				[]byte(mnemonic),
				[]byte("mnemonic"+password),
				2048,
				64,
				sha512.New,
			)
			got := NewSeed(mnemonic, password)
			if !compareByteSlices(got, want) {
				t.Errorf(
					"ASCII seed changed for mnemonic %q password %q: got %x, want %x",
					mnemonic,
					password,
					got,
					want,
				)
			}
		}
	}
}

// Not t.Parallel: SetWordList replaces the package-level wordList and wordMap,
// which every other test in this package reads.
func TestJapaneseVectorsThroughValidationPath(t *testing.T) {
	vectors := loadBIP32JPVectors(t)
	SetWordList(wordlists.Japanese)
	t.Cleanup(func() { SetWordList(wordlists.English) })

	for _, v := range vectors {
		if !IsMnemonicValid(v.Mnemonic) {
			t.Errorf("mnemonic for entropy %s rejected as invalid", v.Entropy)
			continue
		}
		entropy, err := EntropyFromMnemonic(v.Mnemonic)
		if err != nil {
			t.Errorf("EntropyFromMnemonic(%s): %v", v.Entropy, err)
			continue
		}
		if got := hex.EncodeToString(entropy); got != v.Entropy {
			t.Errorf("entropy mismatch: got %s, want %s", got, v.Entropy)
		}
		raw, err := MnemonicToByteArray(v.Mnemonic, true)
		if err != nil {
			t.Errorf("MnemonicToByteArray(%s): %v", v.Entropy, err)
			continue
		}
		if got := hex.EncodeToString(raw); got != v.Entropy {
			t.Errorf("raw byte array mismatch: got %s, want %s", got, v.Entropy)
		}
		seed, err := NewSeedWithErrorChecking(v.Mnemonic, v.Passphrase)
		if err != nil {
			t.Errorf("NewSeedWithErrorChecking(%s): %v", v.Entropy, err)
			continue
		}
		if got := hex.EncodeToString(seed); got != v.Seed {
			t.Errorf("seed mismatch: got %s, want %s", got, v.Seed)
		}
	}
}

// TestTokenizationIsConsistent proves validation and conversion agree on a
// mnemonic whose words are not separated by exactly one ASCII space. They must
// not disagree once normalization runs, because a sentence accepted by
// IsMnemonicValid is exactly the set NewSeedWithErrorChecking will derive from.
func TestTokenizationIsConsistent(t *testing.T) {
	t.Parallel()
	canonical := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	for _, mnemonic := range []string{
		canonical,
		strings.Replace(canonical, " ", "  ", 1),
		strings.Replace(canonical, " ", "　", 1),
		canonical + "\n",
	} {
		valid := IsMnemonicValid(mnemonic)
		_, err := MnemonicToByteArray(mnemonic)
		if valid != (err == nil) {
			t.Errorf(
				"tokenization disagreement for %q: IsMnemonicValid=%v, MnemonicToByteArray err=%v",
				mnemonic,
				valid,
				err,
			)
		}
	}
}
