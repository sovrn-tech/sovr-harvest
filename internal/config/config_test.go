package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
[[validator]]
operator_address = "sovrvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpwmje0"
mnemonic_ref = "op://sovr/validator/mnemonic"
`

func TestDefaults(t *testing.T) {
	c, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainID != "sovr-1" || c.ClaimInterval.Duration != 24*time.Hour || c.GasPriceCoin().String() != "0.002000000000000000usovr" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	v := c.Validators[0]
	if v.HDPath != DefaultHDPath || v.MinClaim != 1_000_000 || !v.WantCommission() || !v.WantSelfDelegation() {
		t.Fatalf("unexpected validator defaults: %+v", v)
	}
	if v.Restake || v.MinRestake != 1_000_000 || v.Reserve().Int64() != DefaultRestakeReserve || c.RestakeInterval.Duration != 24*time.Hour {
		t.Fatalf("unexpected restake defaults: %+v", v)
	}
}

func TestGrantee(t *testing.T) {
	grantee := sdk.AccAddress(bytes.Repeat([]byte{1}, 20)).String()
	c, err := Load(write(t, minimal+"grantee_address = \""+grantee+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Validators[0].Grantee(); got.String() != grantee {
		t.Fatalf("Grantee() = %s, want %s", got, grantee)
	}
	if c, _ := Load(write(t, minimal)); c.Validators[0].Grantee() != nil {
		t.Fatal("Grantee() not nil without grantee_address")
	}
}

func TestRestakeReserve(t *testing.T) {
	grantee := sdk.AccAddress(bytes.Repeat([]byte{1}, 20)).String()
	// With a grantee, the grantee pays the fees. Thus, a reserve of 0 is
	// correct.
	c, err := Load(write(t, minimal+"restake = true\nrestake_reserve = 0\ngrantee_address = \""+grantee+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Validators[0].Reserve().IsZero() {
		t.Fatalf("Reserve() = %s, want 0", c.Validators[0].Reserve())
	}
}

func TestPlaintextRemote(t *testing.T) {
	for ep, want := range map[string]bool{
		"127.0.0.1:9090":                false,
		"[::1]:9090":                    false,
		"localhost:9090":                false,
		"unix:///run/sovr.sock":         false,
		"10.0.0.5:9090":                 true,
		"grpc.sovrchain.net:443":        true,
		"dns:///node.lan:9090":          true,
		"dns:///localhost:9090":         false,
		"dns://8.8.8.8/node.lan:9090":   true,
		"passthrough:///127.0.0.1:9090": false,
		"passthrough:///10.0.0.5:9090":  true,
		"unix-abstract:sovr":            false,
	} {
		c := Config{GRPCEndpoint: ep, GRPCInsecure: true}
		if got := c.PlaintextRemote(); got != want {
			t.Errorf("%s: PlaintextRemote() = %v, want %v", ep, got, want)
		}
	}
	if (&Config{GRPCEndpoint: "10.0.0.5:9090"}).PlaintextRemote() {
		t.Error("PlaintextRemote() true without grpc_insecure")
	}
}

func TestSecretsFile(t *testing.T) {
	body := strings.Replace(minimal, `"op://sovr/validator/mnemonic"`, `"file://validator1"`, 1) +
		"[secrets_file]\npath = \"/run/secrets/mnemonics.toml\"\n"
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretsFile.Path != "/run/secrets/mnemonics.toml" {
		t.Fatalf("SecretsFile.Path = %q", c.SecretsFile.Path)
	}
	if c.Validators[0].MnemonicRef != "file://validator1" {
		t.Fatalf("MnemonicRef = %q", c.Validators[0].MnemonicRef)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":                   minimal + "bogus = 1\n",
		"plain mnemonic":                strings.Replace(minimal, `"op://sovr/validator/mnemonic"`, `"abandon abandon"`, 1),
		"file ref without secrets_file": strings.Replace(minimal, `"op://sovr/validator/mnemonic"`, `"file://validator1"`, 1),
		"account address":               strings.Replace(minimal, "sovrvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpwmje0", "sovr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkn2gdw", 1),
		"gas denom":                     "gas_price = \"0.1uatom\"\n" + minimal,
		"short interval":                "claim_interval = \"5m\"\n" + minimal,
		"nothing to claim":              minimal + "claim_commission = false\nclaim_self_delegation = false\n",
		"no validators":                 "chain_id = \"sovr-1\"\n",
		"grantee is operator":           minimal + "grantee_address = \"sovr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkn2gdw\"\n",
		"grantee valoper":               minimal + "grantee_address = \"sovrvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpwmje0\"\n",
		"gas_adjustment nan":            "gas_adjustment = nan\n" + minimal,
		"gas_adjustment inf":            "gas_adjustment = inf\n" + minimal,
		"gas_adjustment huge":           "gas_adjustment = 11.0\n" + minimal,
		"bad hd_path":                   minimal + "hd_path = \"m/44'/118'/x/0/0\"\n",
		"reserve below max_fee":         minimal + "restake = true\nrestake_reserve = 1000\n",
		"negative reserve":              minimal + "restake_reserve = -1\n",
		"negative min_restake":          minimal + "min_restake = -1\n",
		"short restake_interval":        "restake_interval = \"5m\"\n" + minimal,
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
