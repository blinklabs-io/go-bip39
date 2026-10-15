// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package bip39

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/blinklabs-io/go-bip39/wordlists"
)

func cloneList(l []string) []string { return append([]string(nil), l...) }

func TestValidateWordList(t *testing.T) {
	t.Parallel()
	for name, list := range map[string][]string{
		"english":  wordlists.English,
		"japanese": wordlists.Japanese,
		"chinese":  wordlists.ChineseSimplified,
		"korean":   wordlists.Korean,
	} {
		if err := ValidateWordList(list); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	dup := cloneList(wordlists.English)
	dup[5] = dup[4]
	empty := cloneList(wordlists.English)
	empty[7] = ""
	space := cloneList(wordlists.English)
	space[7] = "two words"
	nfc := cloneList(wordlists.English)
	nfc[7] = "é" // composed, not NFKD
	for name, list := range map[string][]string{
		"nil":        nil,
		"short":      wordlists.English[:2047],
		"long":       append(cloneList(wordlists.English), "extra"),
		"duplicate":  dup,
		"empty word": empty,
		"whitespace": space,
		"not nfkd":   nfc,
	} {
		if err := ValidateWordList(list); !errors.Is(err, ErrInvalidWordList) {
			t.Errorf("%s: got %v, want ErrInvalidWordList", name, err)
		}
	}
}

// Not parallel: SetWordList replaces package state every other test reads.
func TestSetWordListRejectsInvalidList(t *testing.T) {
	t.Cleanup(func() { SetWordList(wordlists.English) })
	SetWordList(wordlists.Spanish)

	dup := cloneList(wordlists.English)
	dup[1] = dup[0]
	for _, bad := range [][]string{wordlists.English[:100], dup, {}} {
		SetWordList(bad)
		assertEqualStringSlices(t, wordlists.Spanish, GetWordList())
	}
}

// Not parallel: SetWordList replaces package state every other test reads.
func TestWordListIsNotAliased(t *testing.T) {
	t.Cleanup(func() { SetWordList(wordlists.English) })

	in := cloneList(wordlists.English)
	SetWordList(in)
	in[0] = "mutated"
	if _, ok := GetWordIndex("mutated"); ok {
		t.Fatal("caller mutation of the input slice reached the index")
	}
	assertEqualStringSlices(t, wordlists.English, GetWordList())

	got := GetWordList()
	got[0] = "mutated"
	got[1] = got[2]
	assertEqualStringSlices(t, wordlists.English, GetWordList())

	entropy := make([]byte, 16)
	m, err := NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	want := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	assertEqual(t, m, want)
}

// Not parallel: SetWordList replaces package state every other test reads.
// Run under -race. Every mnemonic must be valid for the list that produced it,
// so a reader that straddled a swap would fail to decode its own output.
func TestWordListConcurrentAccess(t *testing.T) {
	t.Cleanup(func() { SetWordList(wordlists.English) })

	lists := [][]string{wordlists.English, wordlists.Spanish}
	states := make([]*wordListState, len(lists))
	for listIdx, list := range lists {
		state := &wordListState{
			words: list,
			index: make(map[string]int, len(list)),
		}
		for index, word := range list {
			state.index[word] = index
		}
		states[listIdx] = state
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				SetWordList(lists[i%2])
			}
		}
	}()

	var readers sync.WaitGroup
	for g := 0; g < 8; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			entropy := make([]byte, 32)
			for i := 0; i < 200; i++ {
				_ = GetWordList()
				_, _ = GetWordIndex("abandon")
				m, err := NewMnemonic(entropy)
				if err != nil {
					errs <- err
					return
				}
				// Each possible word-list snapshot may accept the mnemonic,
				// but any accepted decode must reproduce its source entropy.
				accepted := false
				for _, state := range states {
					out, err := entropyFromMnemonic(state, m)
					if err == nil {
						accepted = true
						if !compareByteSlices(out, entropy) {
							errs <- fmt.Errorf(
								"snapshot decode returned %x, want %x",
								out, entropy,
							)
							return
						}
					}
				}
				if !accepted {
					errs <- fmt.Errorf("no configured list decoded generated mnemonic %q", m)
					return
				}
				if out, err := MnemonicToByteArray(m, true); err == nil &&
					!compareByteSlices(out, entropy) {
					errs <- fmt.Errorf(
						"concurrent decode returned %x, want %x",
						out, entropy,
					)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
