// Package sovr holds the SOVR chain constants. It also holds the global
// cosmos-sdk address config that the SDK types use.
package sovr

import (
	"sync"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	AccountPrefix   = "sovr"
	ValidatorPrefix = "sovrvaloper"
	ConsensusPrefix = "sovrvalcons"
	CoinType        = 118
)

var once sync.Once

// Init sets the bech32 prefixes on the global sdk.Config. You can call it
// more than one time.
func Init() {
	once.Do(func() {
		c := sdk.GetConfig()
		c.SetBech32PrefixForAccount(AccountPrefix, AccountPrefix+"pub")
		c.SetBech32PrefixForValidator(ValidatorPrefix, ValidatorPrefix+"pub")
		c.SetBech32PrefixForConsensusNode(ConsensusPrefix, ConsensusPrefix+"pub")
		c.SetCoinType(CoinType)
		c.Seal()
	})
}
