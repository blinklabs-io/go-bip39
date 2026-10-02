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

// TestNewSeedCanonicalSpacing covers the hazard that this package accepts a
// sentence whose separators are not single spaces: validation tokenizes on
// whitespace runs, so each of these is a valid mnemonic for the same entropy,
// and the seed must therefore be the one the canonical sentence derives. Each
// form is a separate case because a single mixed sentence would pass on the
// strength of whichever form the tokenizer happened to handle.
func TestNewSeedCanonicalSpacing(t *testing.T) {
	t.Parallel()
	// The same sentence with only its last separator replaced, so each case
	// isolates one separator form.
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
			if got := hex.EncodeToString(NewSeed(mnemonic, "TREZOR")); got != canonicalVectorSeed {
				t.Errorf("seed for %q:\n got %s\nwant %s", mnemonic, got, canonicalVectorSeed)
			}
			seed, err := NewSeedWithErrorChecking(mnemonic, "TREZOR")
			if err != nil {
				t.Fatalf("NewSeedWithErrorChecking(%q): %v", mnemonic, err)
			}
			if got := hex.EncodeToString(seed); got != canonicalVectorSeed {
				t.Errorf("checked seed for %q:\n got %s\nwant %s", mnemonic, got, canonicalVectorSeed)
			}
		})
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
