// Package config loads and validates the sovr-harvest TOML config.
//
// The config holds no secrets. It refers to key material with a 1Password
// secret reference (op://vault/item/field) or a key in a local secrets file
// (file://key). The claimer gets the key material only when it signs.
package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"cosmossdk.io/math"
	"github.com/BurntSushi/toml"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/sovrn-tech/sovr-harvest/internal/sovr"
)

const DefaultHDPath = "m/44'/118'/0'/0/0"

type Config struct {
	ChainID      string   `toml:"chain_id"`
	GRPCEndpoint string   `toml:"grpc_endpoint"`
	GRPCInsecure bool     `toml:"grpc_insecure"` // plaintext gRPC, for a node on localhost
	Listen       string   `toml:"listen_address"`
	Denom        string   `toml:"denom"`
	PollInterval Duration `toml:"poll_interval"`
	// ClaimInterval is the minimum time between claims for one validator.
	ClaimInterval Duration `toml:"claim_interval"`
	// ClaimJitter is the maximum random delay that the claimer adds to
	// ClaimInterval.
	ClaimJitter Duration `toml:"claim_jitter"`
	// RestakeInterval is the minimum time between restakes for one
	// validator. The claimer adds a random delay of up to ClaimJitter.
	RestakeInterval Duration `toml:"restake_interval"`
	GasPrice        string   `toml:"gas_price"`
	GasAdjustment   float64  `toml:"gas_adjustment"`
	// MaxFee is the maximum fee of one claim tx, in base denom units.
	MaxFee      int64       `toml:"max_fee"`
	TxTimeout   Duration    `toml:"tx_timeout"`
	Memo        string      `toml:"memo"`
	OnePassword OnePassword `toml:"onepassword"`
	SecretsFile SecretsFile `toml:"secrets_file"`
	Validators  []Validator `toml:"validator"`

	gasPrice sdk.DecCoin
}

type OnePassword struct {
	// TokenFile is the file that holds the service account token. If it is
	// empty, the claimer uses $CREDENTIALS_DIRECTORY/op-service-account-token
	// (systemd LoadCredential), then the OP_SERVICE_ACCOUNT_TOKEN environment
	// variable.
	TokenFile string `toml:"token_file"`
}

// SecretsFile configures the file:// backend. Use it as an alternative to
// 1Password, for hosts that cannot reach it. Path is a local TOML file. Give
// it one key = value pair per mnemonic. Only its owner can read it.
type SecretsFile struct {
	Path string `toml:"path"`
}

type Validator struct {
	OperatorAddress string `toml:"operator_address"`
	// GranteeAddress, if set, is an account that has an authz grant from the
	// operator to withdraw its rewards. The grantee then signs the claims and
	// puts them in a MsgExec. The claimer does not use the operator key.
	GranteeAddress string `toml:"grantee_address"`
	// MnemonicRef is a 1Password secret reference (op://vault/item/field) or
	// a secrets_file key (file://key) for the mnemonic of the signing
	// account. This is the grantee if it is set. If not, it is the operator.
	MnemonicRef string `toml:"mnemonic_ref"`
	HDPath      string `toml:"hd_path"`
	// MinClaim is the minimum total pending reward for a claim tx, in base
	// denom units.
	MinClaim int64 `toml:"min_claim"`
	// ClaimCommission and ClaimSelfDelegation set what the claim tx
	// withdraws. The default of each is true.
	ClaimCommission     *bool `toml:"claim_commission"`
	ClaimSelfDelegation *bool `toml:"claim_self_delegation"`
	// Restake, if true, delegates the spendable balance of the operator
	// account to the validator at regular intervals. The restake keeps
	// RestakeReserve in the account for fees.
	Restake bool `toml:"restake"`
	// RestakeReserve is the balance, in base denom units, that a restake
	// keeps in the operator account. If it is not set, it is
	// DefaultRestakeReserve.
	RestakeReserve *int64 `toml:"restake_reserve"`
	// MinRestake is the minimum amount of a restake tx, in base denom units.
	MinRestake int64 `toml:"min_restake"`
}

// DefaultRestakeReserve is 1 SOVR, 20 times the default max_fee.
const DefaultRestakeReserve = 1_000_000

// Reserve returns the restake_reserve of v.
func (v Validator) Reserve() math.Int {
	if v.RestakeReserve == nil {
		return math.NewInt(DefaultRestakeReserve)
	}
	return math.NewInt(*v.RestakeReserve)
}

func (v Validator) MinRestakeInt() math.Int { return math.NewInt(v.MinRestake) }

func (v Validator) WantCommission() bool { return v.ClaimCommission == nil || *v.ClaimCommission }
func (v Validator) WantSelfDelegation() bool {
	return v.ClaimSelfDelegation == nil || *v.ClaimSelfDelegation
}

// Grantee returns the parsed grantee_address, or nil if it is not set.
// Validate checked it before.
func (v Validator) Grantee() sdk.AccAddress {
	if v.GranteeAddress == "" {
		return nil
	}
	a, _ := sdk.AccAddressFromBech32(v.GranteeAddress)
	return a
}

func (c *Config) GasPriceCoin() sdk.DecCoin { return c.gasPrice }

// PlaintextRemote reports if grpc_insecure is set for an endpoint that is
// not on this host. If so, a person on the network path can read and change
// the responses.
func (c *Config) PlaintextRemote() bool {
	if !c.GRPCInsecure {
		return false
	}
	ep := c.GRPCEndpoint
	if strings.HasPrefix(ep, "unix:") || strings.HasPrefix(ep, "unix-abstract:") {
		return false
	}
	// Drop a gRPC target scheme and authority: dns:///host:port,
	// dns://resolver/host:port, passthrough:///host:port.
	if _, rest, ok := strings.Cut(ep, "://"); ok {
		_, ep, _ = strings.Cut(rest, "/")
	}
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		host = ep
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func (v Validator) MinClaimInt() math.Int { return math.NewInt(v.MinClaim) }

// Duration contains a time.Duration. With it, TOML can use strings such as
// "24h".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func Load(path string) (*Config, error) {
	sovr.Init()
	c := &Config{
		ChainID:         "sovr-1",
		GRPCEndpoint:    "grpc.sovrchain.net:443",
		Listen:          "127.0.0.1:9657",
		Denom:           "usovr",
		PollInterval:    Duration{5 * time.Minute},
		ClaimInterval:   Duration{24 * time.Hour},
		ClaimJitter:     Duration{30 * time.Minute},
		RestakeInterval: Duration{24 * time.Hour},
		GasPrice:        "0.002usovr",
		GasAdjustment:   1.4,
		MaxFee:          50_000,
		TxTimeout:       Duration{2 * time.Minute},
	}
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		keys := make([]string, len(undec))
		for i, k := range undec {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	for i := range c.Validators {
		if c.Validators[i].HDPath == "" {
			c.Validators[i].HDPath = DefaultHDPath
		}
		if c.Validators[i].MinClaim == 0 {
			c.Validators[i].MinClaim = 1_000_000
		}
		if c.Validators[i].MinRestake == 0 {
			c.Validators[i].MinRestake = 1_000_000
		}
	}
	return c, c.Validate()
}

// Validate checks the config and parses derived fields. Load calls it.
func (c *Config) Validate() error {
	sovr.Init()
	var errs []error
	if c.ChainID == "" {
		errs = append(errs, errors.New("chain_id is required"))
	}
	if c.GRPCEndpoint == "" {
		errs = append(errs, errors.New("grpc_endpoint is required"))
	}
	gp, err := sdk.ParseDecCoin(c.GasPrice)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("gas_price: %w", err))
	case gp.Denom != c.Denom:
		errs = append(errs, fmt.Errorf("gas_price denom %q does not match denom %q", gp.Denom, c.Denom))
	case !gp.Amount.IsPositive():
		errs = append(errs, errors.New("gas_price must be positive"))
	}
	c.gasPrice = gp
	// This form of the test also fails for NaN.
	if !(c.GasAdjustment >= 1 && c.GasAdjustment <= 10) {
		errs = append(errs, errors.New("gas_adjustment must be between 1 and 10"))
	}
	if c.MaxFee <= 0 {
		errs = append(errs, errors.New("max_fee must be positive"))
	}
	if c.PollInterval.Duration < 10*time.Second {
		errs = append(errs, errors.New("poll_interval must be at least 10s"))
	}
	if c.ClaimInterval.Duration < time.Hour {
		errs = append(errs, errors.New("claim_interval must be at least 1h"))
	}
	if c.RestakeInterval.Duration < time.Hour {
		errs = append(errs, errors.New("restake_interval must be at least 1h"))
	}
	if c.TxTimeout.Duration < 10*time.Second {
		errs = append(errs, errors.New("tx_timeout must be at least 10s"))
	}
	if c.ClaimJitter.Duration < 0 {
		errs = append(errs, errors.New("claim_jitter must not be negative"))
	}
	if len(c.Validators) == 0 {
		errs = append(errs, errors.New("at least one [[validator]] is required"))
	}
	seen := map[string]bool{}
	for i, v := range c.Validators {
		p := fmt.Sprintf("validator[%d]", i)
		valoper, err := sdk.ValAddressFromBech32(v.OperatorAddress)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.operator_address: %w", p, err))
		}
		if v.GranteeAddress != "" {
			grantee, err := sdk.AccAddressFromBech32(v.GranteeAddress)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s.grantee_address: %w", p, err))
			case valoper != nil && grantee.Equals(sdk.AccAddress(valoper)):
				errs = append(errs, fmt.Errorf("%s.grantee_address is the operator account; use a separate key", p))
			}
		}
		if seen[v.OperatorAddress] {
			errs = append(errs, fmt.Errorf("%s: duplicate operator_address", p))
		}
		seen[v.OperatorAddress] = true
		// Parse the path with the derivation code, on a dummy master key. Thus, a
		// bad path fails here, and not after the claimer gets the mnemonic.
		if _, err := hd.DerivePrivateKeyForPath([32]byte{1}, [32]byte{}, v.HDPath); err != nil {
			errs = append(errs, fmt.Errorf("%s.hd_path: %w", p, err))
		}
		switch {
		case strings.HasPrefix(v.MnemonicRef, "op://"):
		case strings.HasPrefix(v.MnemonicRef, "file://"):
			if c.SecretsFile.Path == "" {
				errs = append(errs, fmt.Errorf("%s.mnemonic_ref is file:// but secrets_file.path is not set", p))
			}
		default:
			errs = append(errs, fmt.Errorf("%s.mnemonic_ref must be an op:// or file:// secret reference", p))
		}
		if v.MinClaim < 0 {
			errs = append(errs, fmt.Errorf("%s.min_claim must not be negative", p))
		}
		if !v.WantCommission() && !v.WantSelfDelegation() {
			errs = append(errs, fmt.Errorf("%s: claim_commission and claim_self_delegation are both false", p))
		}
		if v.MinRestake < 0 {
			errs = append(errs, fmt.Errorf("%s.min_restake must not be negative", p))
		}
		switch {
		case v.Reserve().IsNegative():
			errs = append(errs, fmt.Errorf("%s.restake_reserve must not be negative", p))
		case v.Restake && v.GranteeAddress == "" && v.Reserve().LT(math.NewInt(c.MaxFee)):
			// Without a grantee, the operator pays the claim fees from the reserve.
			errs = append(errs, fmt.Errorf("%s.restake_reserve must be at least max_fee, because the operator pays the claim fees", p))
		}
	}
	return errors.Join(errs...)
}
