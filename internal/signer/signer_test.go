package signer

import (
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"

	"github.com/sovrn-tech/sovr-harvest/internal/sovr"
)

const path = "m/44'/118'/0'/0/0"

func newMnemonic(t *testing.T) (string, sdk.AccAddress) {
	t.Helper()
	e, _ := bip39.NewEntropy(256)
	m, _ := bip39.NewMnemonic(e)
	bz, err := hd.Secp256k1.Derive()(m, "", path)
	if err != nil {
		t.Fatal(err)
	}
	return m, sdk.AccAddress(hd.Secp256k1.Generate()(bz).PubKey().Address())
}

func TestDeriveWipesInputAndKey(t *testing.T) {
	sovr.Init()
	m, addr := newMnemonic(t)
	// Extra whitespace, which a copy and paste into 1Password can add.
	in := []byte("  " + strings.ReplaceAll(m, " ", "\n ") + "\n")
	k, err := Derive(in, path, addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range in {
		if b != 0 {
			t.Fatal("mnemonic buffer not wiped")
		}
	}
	if !strings.HasPrefix(k.Address().String(), "sovr1") {
		t.Fatalf("address %s lacks sovr prefix", k.Address())
	}
	raw := k.priv.Key
	k.Wipe()
	for _, b := range raw {
		if b != 0 {
			t.Fatal("private key not wiped")
		}
	}
	k.Wipe() // idempotent
}

func TestDeriveRejectsWrongAccount(t *testing.T) {
	m, _ := newMnemonic(t)
	_, other := newMnemonic(t)
	if _, err := Derive([]byte(m), path, other); err == nil {
		t.Fatal("expected mismatch error")
	}
}
