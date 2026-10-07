package bip39

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// The first English vector of BIP-39, entropy 0x00 repeated, passphrase
// "TREZOR". Pinned rather than recomputed: the point of these tests is that a
// non-canonically spaced sentence reaches the published seed, so deriving the
// expectation from NewSeed would assert nothing.
const (
	canonicalVectorMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	canonicalVectorEntropy  = "00000000000000000000000000000000"
	canonicalVectorSeed     = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)

// TestNewSeedMnemonicWhitespacePreserved verifies that NewSeed applies NFKD
// without changing the mnemonic's whitespace. Validation accepts whitespace
// variants as the same words, but derivation preserves their normalized input
// for compatibility with existing callers.
func TestNewSeedMnemonicWhitespacePreserved(t *testing.T) {
	t.Parallel()
	lastSep := func(sep string) string {
		return strings.Repeat("abandon ", 10) + "abandon" + sep + "about"
	}
	for name, mnemonic := range map[string]string{
		"doubledSpace":     "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"tripledSpace":     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon   abandon about",
		"tab":              "abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"newline":          "abandon\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"carriageReturn":   "abandon\r\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"leadingSpace":     " " + canonicalVectorMnemonic,
		"trailingSpace":    canonicalVectorMnemonic + " ",
		"trailingNewline":  canonicalVectorMnemonic + "\n",
		"ideographicSpace": lastSep("\u3000"),
		"doubledIdeograph": lastSep("\u3000\u3000"),
		"noBreakSpace":     lastSep("\u00a0"),
		"mixedRun":         " \t" + canonicalVectorMnemonic + "\u3000\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !IsMnemonicValid(mnemonic) {
				t.Fatalf("mnemonic %q rejected; the seed hazard only exists because it is accepted", mnemonic)
			}
			entropy, err := EntropyFromMnemonic(mnemonic)
			if err != nil {
				t.Fatalf("EntropyFromMnemonic(%q): %v", mnemonic, err)
			}
			if got := hex.EncodeToString(entropy); got != canonicalVectorEntropy {
				t.Fatalf("entropy for %q: got %s, want %s", mnemonic, got, canonicalVectorEntropy)
			}
			want := pbkdf2.Key(
				[]byte(normalizeString(mnemonic)),
				[]byte("mnemonic"+normalizeString("TREZOR")),
				2048,
				64,
				sha512.New,
			)
			if got := NewSeed(mnemonic, "TREZOR"); !compareByteSlices(got, want) {
				t.Errorf("seed for %q:\n got %x\nwant %x", mnemonic, got, want)
			}
			seed, err := NewSeedWithErrorChecking(mnemonic, "TREZOR")
			if err != nil {
				t.Fatalf("NewSeedWithErrorChecking(%q): %v", mnemonic, err)
			}
			if !compareByteSlices(seed, want) {
				t.Errorf("checked seed for %q:\n got %x\nwant %x", mnemonic, seed, want)
			}
		})
	}
	spaced := strings.Replace(canonicalVectorMnemonic, " ", "  ", 1)
	if compareByteSlices(NewSeed(canonicalVectorMnemonic, "TREZOR"), NewSeed(spaced, "TREZOR")) {
		t.Error("mnemonic spacing did not affect the derived seed")
	}
	if got := NewSeed(lastSep("\u3000"), "TREZOR"); !compareByteSlices(got, NewSeed(canonicalVectorMnemonic, "TREZOR")) {
		t.Error("NFKD-equivalent ideographic separator changed the derived seed")
	}
}

// TestNewSeedPassphraseSpacingIsSignificant holds the other side of the
// contract. A passphrase is an opaque string, not a word sentence, so its own
// spacing selects a different wallet and must survive into the salt untouched.
func TestNewSeedPassphraseSpacingIsSignificant(t *testing.T) {
	t.Parallel()
	for _, password := range []string{" ", "  ", " pass", "pass ", "two  spaces", "two spaces", "tab\there", "\u3000"} {
		want := pbkdf2.Key(
			[]byte(canonicalVectorMnemonic),
			[]byte("mnemonic"+normalizeString(password)),
			2048,
			64,
			sha512.New,
		)
		got := NewSeed(canonicalVectorMnemonic, password)
		if !compareByteSlices(got, want) {
			t.Errorf("passphrase %q was not hashed as given: got %x, want %x", password, got, want)
		}
	}
	if compareByteSlices(
		NewSeed(canonicalVectorMnemonic, "two  spaces"),
		NewSeed(canonicalVectorMnemonic, "two spaces"),
	) {
		t.Error("passphrases differing only in spacing collided")
	}
}
