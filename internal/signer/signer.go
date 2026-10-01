// Package signer derives a short-lived secp256k1 key from a mnemonic. Before
// the key signs, the package makes sure that the key is for the correct
// account.
package signer

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/sovrn-tech/sovr-harvest/internal/secret"
)

// Key is a derived private key. After you use it, call Wipe.
type Key struct {
	priv *secp256k1.PrivKey
}

// Derive derives the key at hdPath from mnemonic. It makes sure that the
// address of the key is want, the account that must sign (the grantee or the
// operator). Derive writes zeros over the mnemonic slice before it returns.
func Derive(mnemonic []byte, hdPath string, want sdk.AccAddress) (*Key, error) {
	defer secret.Wipe(mnemonic)
	// go-bip39 takes only a string. We cannot write zeros over this copy.
	words := strings.Join(strings.Fields(string(mnemonic)), " ")
	bz, err := hd.Secp256k1.Derive()(words, "", hdPath)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	priv, ok := hd.Secp256k1.Generate()(bz).(*secp256k1.PrivKey)
	secret.Wipe(bz)
	if !ok {
		return nil, fmt.Errorf("derive key: unexpected key type")
	}
	k := &Key{priv: priv}
	if got := k.Address(); !bytes.Equal(got, want) {
		k.Wipe()
		return nil, fmt.Errorf("derived address %s does not match signing account %s: wrong mnemonic or hd_path", got, want)
	}
	return k, nil
}

func (k *Key) PrivKey() cryptotypes.PrivKey { return k.priv }
func (k *Key) PubKey() cryptotypes.PubKey   { return k.priv.PubKey() }
func (k *Key) Address() sdk.AccAddress      { return sdk.AccAddress(k.priv.PubKey().Address()) }

// Wipe writes zeros over the private key bytes.
func (k *Key) Wipe() {
	if k != nil && k.priv != nil {
		secret.Wipe(k.priv.Key)
		k.priv = nil
	}
}
