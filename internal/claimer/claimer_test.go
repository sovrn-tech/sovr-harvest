package claimer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	stdmath "math"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/math"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/go-bip39"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sovrn-tech/sovr-harvest/internal/chain"
	"github.com/sovrn-tech/sovr-harvest/internal/config"
	"github.com/sovrn-tech/sovr-harvest/internal/metrics"
	"github.com/sovrn-tech/sovr-harvest/internal/sovr"
)

const ref = "op://vault/validator/mnemonic"

type fakeChain struct {
	snap      chain.Snapshot
	gas       uint64
	signed    int
	broadcast int
	lastTx    chain.Tx
	simPub    cryptotypes.PubKey
	simErr    error
	signErr   error
	txErr     error // WaitTx finds no tx
	txFailed  bool  // WaitTx finds the tx, which failed
	waits     int
	calls     []string
	// withdrawQueries records, for each snapshot, if the claimer asked for
	// the withdraw address.
	withdrawQueries []bool
}

func (f *fakeChain) Snapshot(_ context.Context, _ sdk.ValAddress, _ string, _ sdk.AccAddress, withdraw bool) (*chain.Snapshot, error) {
	f.calls = append(f.calls, "snapshot")
	f.withdrawQueries = append(f.withdrawQueries, withdraw)
	s := f.snap
	if !withdraw {
		s.WithdrawAddress, s.WithdrawAddressErr = nil, nil
	}
	return &s, nil
}
func (f *fakeChain) Simulate(_ context.Context, tx chain.Tx, pub cryptotypes.PubKey, _ uint64) (uint64, error) {
	f.lastTx = tx
	f.simPub = pub
	return f.gas, f.simErr
}
func (f *fakeChain) Sign(_ context.Context, tx chain.Tx, _ cryptotypes.PrivKey, _ string, _, _ uint64) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	f.signed++
	f.lastTx = tx
	return []byte("signed"), nil
}
func (f *fakeChain) Broadcast(context.Context, []byte) (string, error) {
	f.broadcast++
	return "ABCD", nil
}
func (f *fakeChain) WaitTx(context.Context, string) (*sdk.TxResponse, error) {
	f.waits++
	f.calls = append(f.calls, "wait")
	if f.txErr != nil {
		return nil, f.txErr
	}
	if f.txFailed {
		return &sdk.TxResponse{Height: 10, Code: 5}, chain.ErrTxFailed
	}
	return &sdk.TxResponse{Height: 10, GasUsed: 150000, Events: []abci.Event{
		{Type: "withdraw_commission", Attributes: []abci.EventAttribute{{Key: "amount", Value: "1200000usovr"}}},
		{Type: "withdraw_rewards", Attributes: []abci.EventAttribute{{Key: "amount", Value: "3800000usovr"}, {Key: "validator", Value: "x"}}},
	}}, nil
}

type countingSecrets struct {
	mnemonic string
	fetches  int
}

func (c *countingSecrets) Fetch(context.Context, string) ([]byte, error) {
	c.fetches++
	return []byte(c.mnemonic), nil
}

type fixture struct {
	mnemonic string // operator mnemonic
	cl       *Claimer
	chain    *fakeChain
	secrets  *countingSecrets
	m        *metrics.Metrics
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sovr.Init()
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	bz, err := hd.Secp256k1.Derive()(mnemonic, "", config.DefaultHDPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := hd.Secp256k1.Generate()(bz).PubKey()
	acc := sdk.AccAddress(pub.Address())

	cfg := &config.Config{
		ChainID: "sovr-1", GRPCEndpoint: "fake:443", Denom: "usovr", GasPrice: "0.002usovr", GasAdjustment: 1.5,
		MaxFee: 50000, PollInterval: config.Duration{Duration: time.Minute},
		ClaimInterval:   config.Duration{Duration: 24 * time.Hour},
		RestakeInterval: config.Duration{Duration: 24 * time.Hour},
		TxTimeout:       config.Duration{Duration: time.Minute},
		Validators: []config.Validator{{
			OperatorAddress: sdk.ValAddress(acc).String(), MnemonicRef: ref,
			HDPath: config.DefaultHDPath, MinClaim: 1_000_000,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	fc := &fakeChain{gas: 200000, snap: chain.Snapshot{
		ChainID: "sovr-1", Height: 100, BlockTime: time.Unix(1_800_000_000, 0),
		Operator:        chain.Account{Address: acc, AccountNumber: 186, Sequence: 3, PubKey: pub, Balance: math.NewInt(7_000_000)},
		WithdrawAddress: acc,
		Tokens:          math.NewInt(1), Outstanding: math.NewInt(6_000_000),
		Commission: math.NewInt(1_200_000), SelfRewards: math.NewInt(3_800_000), Bonded: true,
	}}
	sec := &countingSecrets{mnemonic: mnemonic}
	m := metrics.New("test", "sovr-1")
	f := &fixture{mnemonic: mnemonic, chain: fc, secrets: sec, m: m, now: time.Unix(1_800_000_000, 0)}
	f.cl = New(cfg, fc, sec, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.cl.now = func() time.Time { return f.now }
	f.cl.jitter = func(time.Duration) time.Duration { return 0 }
	return f
}

func (f *fixture) attempts(result string) float64 {
	return testutil.ToFloat64(f.m.ClaimAttempts.WithLabelValues(f.cl.cfg.Validators[0].OperatorAddress, result))
}

func TestDryRunNeverFetchesSecret(t *testing.T) {
	f := newFixture(t)
	if err := f.cl.Poll(context.Background(), ModeDryRun); err != nil {
		t.Fatal(err)
	}
	if f.secrets.fetches != 0 || f.chain.signed != 0 || f.chain.broadcast != 0 {
		t.Fatalf("dry run touched key or chain: fetches=%d signed=%d broadcast=%d", f.secrets.fetches, f.chain.signed, f.chain.broadcast)
	}
	if f.attempts("dry_run") != 1 {
		t.Fatal("dry_run not counted")
	}
}

func TestBelowThresholdNeverFetchesSecret(t *testing.T) {
	f := newFixture(t)
	f.chain.snap.Commission = math.NewInt(100)
	f.chain.snap.SelfRewards = math.NewInt(200)
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.secrets.fetches != 0 || f.chain.broadcast != 0 {
		t.Fatal("below-threshold poll fetched the secret or broadcast")
	}
	if f.attempts("below_threshold") != 1 {
		t.Fatal("below_threshold not counted")
	}
}

func TestNoPubKeySimulatesBeforeFetchingSecret(t *testing.T) {
	f := newFixture(t)
	f.chain.snap.Operator.PubKey = nil
	f.chain.snap.Operator.Balance = math.ZeroInt()
	if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
		t.Fatal("expected insufficient balance error")
	}
	if pk, ok := f.chain.simPub.(*secp256k1.PubKey); !ok || len(pk.Key) != 0 {
		t.Fatalf("simulated with %v, want empty secp256k1 placeholder", f.chain.simPub)
	}
	if f.secrets.fetches != 0 {
		t.Fatal("secret fetched before the fee checks passed")
	}
}

func TestNoPubKeyClaims(t *testing.T) {
	f := newFixture(t)
	f.chain.snap.Operator.PubKey = nil
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.secrets.fetches != 1 || f.chain.signed != 1 || f.attempts("success") != 1 {
		t.Fatalf("fetches=%d signed=%d", f.secrets.fetches, f.chain.signed)
	}
}

func TestClaimThenWaitForInterval(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.secrets.fetches != 1 || f.chain.broadcast != 1 {
		t.Fatalf("want one fetch and one broadcast, got %d and %d", f.secrets.fetches, f.chain.broadcast)
	}
	if n := len(f.chain.lastTx.Msgs); n != 2 {
		t.Fatalf("want 2 msgs, got %d", n)
	}
	// gas 200000 * 1.5 = 300000, * 0.002 = 600 usovr
	if got := f.chain.lastTx.Fee.AmountOf("usovr"); !got.Equal(math.NewInt(600)) {
		t.Fatalf("fee = %s, want 600", got)
	}
	val := f.cl.cfg.Validators[0].OperatorAddress
	if got := testutil.ToFloat64(f.m.Claimed.WithLabelValues(val, SourceCommission)); got != 1_200_000 {
		t.Fatalf("claimed commission metric = %v", got)
	}

	// The rewards are still above the threshold, but the interval did not pass.
	f.now = f.now.Add(23 * time.Hour)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.broadcast != 1 {
		t.Fatal("claimed before claim_interval elapsed")
	}
	f.now = f.now.Add(2 * time.Hour)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.broadcast != 2 || f.secrets.fetches != 2 {
		t.Fatal("did not claim after claim_interval, or reused a cached secret")
	}
}

func TestWrongMnemonicRefusesToSign(t *testing.T) {
	f := newFixture(t)
	entropy, _ := bip39.NewEntropy(256)
	f.secrets.mnemonic, _ = bip39.NewMnemonic(entropy)
	err := f.cl.Poll(context.Background(), ModeScheduled)
	if err == nil {
		t.Fatal("expected address mismatch error")
	}
	if f.chain.signed != 0 {
		t.Fatal("signed with the wrong key")
	}
}

func TestInsufficientBalanceBacksOff(t *testing.T) {
	f := newFixture(t)
	f.chain.snap.Operator.Balance = math.NewInt(10)
	if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
		t.Fatal("expected error")
	}
	if f.secrets.fetches != 0 {
		t.Fatal("fetched secret although the fee cannot be paid")
	}
	st := f.cl.claims.sched[f.cl.cfg.Validators[0].OperatorAddress]
	if want := f.now.Add(retryBase); !st.next.Equal(want) {
		t.Fatalf("next = %v, want %v", st.next, want)
	}
}

func TestFailedTxBacksOff(t *testing.T) {
	f := newFixture(t)
	f.chain.txFailed = true
	for range 3 {
		_ = f.cl.Poll(context.Background(), ModeForce)
	}
	st := f.cl.claims.sched[f.cl.cfg.Validators[0].OperatorAddress]
	if st.failures != 3 || !st.next.Equal(f.now.Add(4*retryBase)) {
		t.Fatalf("failures=%d next=%v", st.failures, st.next.Sub(f.now))
	}
}

func TestPlanRespectsToggles(t *testing.T) {
	f := newFixture(t)
	v := f.cl.cfg.Validators[0]
	no := false
	v.ClaimSelfDelegation = &no
	msgs, total := Plan(v, &f.chain.snap)
	if len(msgs) != 1 || !total.Equal(math.NewInt(1_200_000)) {
		t.Fatalf("msgs=%d total=%s", len(msgs), total)
	}
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 5 * time.Minute, 2: 10 * time.Minute, 7: 320 * time.Minute, 20: retryMax} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// withGrantee sets f to authz mode. A separate grantee key signs, the
// secret provider holds the grantee mnemonic, and both grants exist.
func (f *fixture) withGrantee(t *testing.T) *chain.Account {
	t.Helper()
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	bz, err := hd.Secp256k1.Derive()(mnemonic, "", config.DefaultHDPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := hd.Secp256k1.Generate()(bz).PubKey()
	g := &chain.Account{Address: sdk.AccAddress(pub.Address()), AccountNumber: 900, Sequence: 7, PubKey: pub, Balance: math.NewInt(1_000_000)}

	f.cl.cfg.Validators[0].GranteeAddress = g.Address.String()
	if err := f.cl.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	f.secrets.mnemonic = mnemonic
	exp := f.now.Add(365 * 24 * time.Hour)
	f.chain.snap.Grantee = g
	f.chain.snap.Grants = map[string]chain.Grant{
		msgTypeCommission:     {Expiry: &exp, Authorization: authz.NewGenericAuthorization(msgTypeCommission)},
		msgTypeSelfDelegation: {Authorization: authz.NewGenericAuthorization(msgTypeSelfDelegation)},
	}
	return g
}

func (f *fixture) grantExpiry(typ string) float64 {
	return testutil.ToFloat64(f.m.GrantExpiry.WithLabelValues(f.cl.cfg.Validators[0].OperatorAddress, typ))
}

func TestGranteeClaimWrapsInExec(t *testing.T) {
	f := newFixture(t)
	g := f.withGrantee(t)
	f.chain.snap.Operator.Balance = math.ZeroInt() // the grantee pays the fee
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.signed != 1 || f.attempts("success") != 1 {
		t.Fatalf("signed=%d", f.chain.signed)
	}
	if len(f.chain.lastTx.Msgs) != 1 {
		t.Fatalf("want 1 msg, got %d", len(f.chain.lastTx.Msgs))
	}
	exec, ok := f.chain.lastTx.Msgs[0].(*authz.MsgExec)
	if !ok || exec.Grantee != g.Address.String() {
		t.Fatalf("want MsgExec from grantee, got %T %+v", f.chain.lastTx.Msgs[0], f.chain.lastTx.Msgs[0])
	}
	inner, err := exec.GetMessages()
	if err != nil || len(inner) != 2 {
		t.Fatalf("inner=%v err=%v", inner, err)
	}
	if d := inner[1].(*distrtypes.MsgWithdrawDelegatorReward).DelegatorAddress; d != f.chain.snap.Operator.Address.String() {
		t.Fatalf("self-delegation withdraw for %s, want operator", d)
	}
	if !g.PubKey.Equals(f.chain.simPub) {
		t.Fatal("simulated with a pubkey other than the grantee's")
	}
	if got := f.grantExpiry(msgTypeCommission); got != float64(f.now.Add(365*24*time.Hour).Unix()) {
		t.Fatalf("commission grant expiry metric = %v", got)
	}
	if got := f.grantExpiry(msgTypeSelfDelegation); !stdmath.IsInf(got, 1) {
		t.Fatalf("self-delegation grant expiry metric = %v, want +Inf", got)
	}
}

func TestGranteeMissingGrantNeverFetchesSecret(t *testing.T) {
	for name, mutate := range map[string]func(*fixture){
		"missing": func(f *fixture) { delete(f.chain.snap.Grants, msgTypeSelfDelegation) },
		"expiring": func(f *fixture) {
			soon := f.chain.snap.BlockTime.Add(30 * time.Second) // before tx_timeout
			f.chain.snap.Grants[msgTypeCommission] = chain.Grant{Expiry: &soon, Authorization: authz.NewGenericAuthorization(msgTypeCommission)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.withGrantee(t)
			mutate(f)
			if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
				t.Fatal("expected grant error")
			}
			if f.secrets.fetches != 0 || f.chain.signed != 0 {
				t.Fatal("fetched secret or signed without a usable grant")
			}
			if f.attempts("no_grant") != 1 {
				t.Fatal("no_grant not counted")
			}
		})
	}
	f := newFixture(t)
	f.withGrantee(t)
	delete(f.chain.snap.Grants, msgTypeSelfDelegation)
	_ = f.cl.Poll(context.Background(), ModeDryRun)
	if got := f.grantExpiry(msgTypeSelfDelegation); got != 0 {
		t.Fatalf("missing grant metric = %v, want 0", got)
	}
}

func TestGranteeBalancePaysFee(t *testing.T) {
	f := newFixture(t)
	f.withGrantee(t)
	f.chain.snap.Grantee.Balance = math.NewInt(10) // the operator still has sufficient funds
	if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
		t.Fatal("expected insufficient balance error")
	}
	if f.attempts("insufficient_balance") != 1 || f.secrets.fetches != 0 {
		t.Fatal("grantee balance not checked before fetching the secret")
	}
}

func TestGranteeRefusesOperatorMnemonic(t *testing.T) {
	f := newFixture(t)
	f.withGrantee(t)
	f.secrets.mnemonic = f.mnemonic
	if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
		t.Fatal("expected address mismatch error")
	}
	if f.chain.signed != 0 {
		t.Fatal("signed with the operator key in grantee mode")
	}
}

// TestEveryClaimErrorCountsAsFailed covers the stages that failed without a
// change to claim_attempts_total in the past. Thus, the alerts did not see
// them.
func TestEveryClaimErrorCountsAsFailed(t *testing.T) {
	for name, tc := range map[string]struct {
		stage  string
		mutate func(*fixture)
	}{
		"simulate": {"simulate", func(f *fixture) { f.chain.simErr = errors.New("boom") }},
		"wrong mnemonic": {"secret", func(f *fixture) {
			entropy, _ := bip39.NewEntropy(256)
			f.secrets.mnemonic, _ = bip39.NewMnemonic(entropy)
		}},
		"pubkey mismatch": {"secret", func(f *fixture) { f.chain.snap.Operator.PubKey = secp256k1.GenPrivKey().PubKey() }},
		"sign":            {"sign", func(f *fixture) { f.chain.signErr = errors.New("boom") }},
		"confirm":         {"confirm", func(f *fixture) { f.chain.txFailed = true }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.mutate(f)
			if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
				t.Fatal("expected error")
			}
			val := f.cl.cfg.Validators[0].OperatorAddress
			if f.attempts("failed") != 1 {
				t.Fatalf("failed attempts = %v, want 1", f.attempts("failed"))
			}
			if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, tc.stage)); got != 1 {
				t.Fatalf("errors{stage=%q} = %v, want 1", tc.stage, got)
			}
		})
	}
}

// TestPollDuringBackoffIsSuccessful checks that only poll errors change
// last_successful_poll. claim_consecutive_failures reports a claim that
// continues to fail. Thus, that claim must not also stop this timestamp and
// fire a second alert for the same fault.
func TestPollDuringBackoffIsSuccessful(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	lastOK := func() float64 { return testutil.ToFloat64(f.m.LastPollOK) }

	f.chain.txFailed = true
	if err := f.cl.Poll(ctx, ModeScheduled); err == nil {
		t.Fatal("expected error")
	}
	if lastOK() != 0 {
		t.Fatalf("failed poll counted as successful at %v", lastOK())
	}
	f.now = f.now.Add(time.Minute) // still within the 5m backoff
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if want := float64(f.now.Unix()); lastOK() != want {
		t.Fatalf("last successful poll = %v, want %v", lastOK(), want)
	}
}

// TestImplausibleGasRefused covers an untrusted node that reports incorrect
// gas. That gas would make a zero-gas tx, or overflow the fee arithmetic.
func TestImplausibleGasRefused(t *testing.T) {
	for _, gas := range []uint64{0, maxSimGas + 1, stdmath.MaxUint64} {
		f := newFixture(t)
		f.chain.gas = gas
		if err := f.cl.Poll(context.Background(), ModeScheduled); err == nil {
			t.Fatalf("gas %d: expected error", gas)
		}
		if f.secrets.fetches != 0 || f.chain.signed != 0 {
			t.Fatalf("gas %d: fetched secret or signed", gas)
		}
	}
}

func TestConsecutiveFailuresGauge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	val := f.cl.cfg.Validators[0].OperatorAddress
	gauge := func() float64 { return testutil.ToFloat64(f.m.ClaimFailures.WithLabelValues(val)) }

	// The series starts at 0, so increase() shows the first failure.
	if n := testutil.CollectAndCount(f.m.ClaimAttempts); n != len(metrics.ClaimResults) {
		t.Fatalf("claim_attempts_total has %d series, want %d at zero", n, len(metrics.ClaimResults))
	}
	f.chain.txFailed = true
	_ = f.cl.Poll(ctx, ModeForce)
	_ = f.cl.Poll(ctx, ModeForce)
	if gauge() != 2 {
		t.Fatalf("consecutive failures = %v, want 2", gauge())
	}

	// Another tool claimed the rewards. The skip sets the failure count to 0.
	f.chain.snap.Commission = math.ZeroInt()
	f.chain.snap.SelfRewards = math.ZeroInt()
	f.now = f.now.Add(time.Hour)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if gauge() != 0 {
		t.Fatalf("skip did not reset the gauge: %v", gauge())
	}
}

// TestLateConfirmationCounts covers a claim tx that gets into a block after
// tx_timeout. The next poll finds it and records one successful claim, with
// no failure before it.
func TestLateConfirmationCounts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	val := f.cl.cfg.Validators[0].OperatorAddress

	f.chain.txErr = context.DeadlineExceeded
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatalf("confirm timeout reported as an error: %v", err)
	}
	if f.cl.unconfirmed[val] == nil {
		t.Fatal("timed-out tx not remembered")
	}

	f.chain.txErr = nil
	f.chain.calls = nil
	f.now = f.now.Add(time.Minute)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	st := f.cl.claims.sched[val]
	if f.cl.unconfirmed[val] != nil || st.failures != 0 || f.attempts("success") != 1 || f.attempts("failed") != 0 {
		t.Fatalf("late tx not recorded once as a success: unconfirmed=%v failures=%d success=%v failed=%v",
			f.cl.unconfirmed[val], st.failures, f.attempts("success"), f.attempts("failed"))
	}
	if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, "confirm")); got != 0 {
		t.Fatalf("errors{stage=confirm} = %v, want 0", got)
	}
	if !st.next.Equal(f.now.Add(24 * time.Hour)) {
		t.Fatalf("next = %v, want claim_interval from now", st.next.Sub(f.now))
	}
	if got := testutil.ToFloat64(f.m.Claimed.WithLabelValues(val, SourceCommission)); got != 1_200_000 {
		t.Fatalf("claimed commission = %v", got)
	}
	if f.chain.broadcast != 1 {
		t.Fatalf("broadcast %d txs, want 1", f.chain.broadcast)
	}
	// The poll looks for the tx before the snapshot. Thus, a claim in the same
	// poll cannot use the sequence from before the late tx got into a block.
	if len(f.chain.calls) < 2 || f.chain.calls[0] != "wait" || f.chain.calls[1] != "snapshot" {
		t.Fatalf("calls = %v, want the lookup before the snapshot", f.chain.calls)
	}
}

// TestNoRetryWhileUnconfirmed checks that the claimer sends no second claim
// while the first can still get into a block. The second claim would use the
// same sequence. If the first claim got into a block, the claimer would count
// the failure of the retry instead.
func TestNoRetryWhileUnconfirmed(t *testing.T) {
	for _, mode := range []Mode{ModeScheduled, ModeForce} {
		f := newFixture(t)
		ctx := context.Background()
		f.chain.txErr = context.DeadlineExceeded
		_ = f.cl.Poll(ctx, mode)
		for range 3 {
			f.now = f.now.Add(10 * time.Minute)
			if err := f.cl.Poll(ctx, mode); err != nil {
				t.Fatal(err)
			}
		}
		if f.chain.broadcast != 1 || f.secrets.fetches != 1 {
			t.Fatalf("mode %d: broadcast=%d fetches=%d while a tx was unconfirmed, want 1", mode, f.chain.broadcast, f.secrets.fetches)
		}
		if f.attempts("failed") != 0 {
			t.Fatalf("mode %d: pending tx counted as failed", mode)
		}
	}
}

func TestUnconfirmedGivesUp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	val := f.cl.cfg.Validators[0].OperatorAddress
	f.chain.txErr = context.DeadlineExceeded
	_ = f.cl.Poll(ctx, ModeScheduled)

	f.now = f.now.Add(time.Minute)
	_ = f.cl.Poll(ctx, ModeScheduled) // tx still not found
	if f.cl.unconfirmed[val] == nil {
		t.Fatal("gave up too early")
	}
	f.now = f.now.Add(lateGiveUp)
	if err := f.cl.Poll(ctx, ModeScheduled); err == nil {
		t.Fatal("giving up not reported as an error")
	}
	st := f.cl.claims.sched[val]
	if f.cl.unconfirmed[val] != nil {
		t.Fatal("still tracking the tx after lateGiveUp")
	}
	if st.failures != 1 || f.attempts("failed") != 1 || !st.next.Equal(f.now.Add(retryBase)) {
		t.Fatalf("give-up not counted once as a failure: failures=%d failed=%v next=%v",
			st.failures, f.attempts("failed"), st.next.Sub(f.now))
	}
	if f.chain.broadcast != 1 {
		t.Fatal("retried in the poll that gave up, before backing off")
	}
}

// TestUnconfirmedLandedButFailed covers a timed-out tx that a later poll
// finds with a non-zero code. The claimer counts one failure and the fee.
func TestUnconfirmedLandedButFailed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	val := f.cl.cfg.Validators[0].OperatorAddress
	f.chain.txErr = context.DeadlineExceeded
	_ = f.cl.Poll(ctx, ModeScheduled)

	f.chain.txErr = nil
	f.chain.txFailed = true
	f.now = f.now.Add(time.Minute)
	if err := f.cl.Poll(ctx, ModeScheduled); !errors.Is(err, chain.ErrTxFailed) {
		t.Fatalf("err = %v, want ErrTxFailed", err)
	}
	st := f.cl.claims.sched[val]
	if f.cl.unconfirmed[val] != nil || st.failures != 1 || f.attempts("failed") != 1 {
		t.Fatalf("unconfirmed=%v failures=%d failed=%v", f.cl.unconfirmed[val], st.failures, f.attempts("failed"))
	}
	if got := testutil.ToFloat64(f.m.FeesPaid.WithLabelValues(val)); got != 600 {
		t.Fatalf("fees paid = %v, want 600", got)
	}
}

// TestClaimableCountsOnlyClaimedSources checks the gauge that the no-claim
// alert compares with min_claim. A source that the validator does not claim
// must not count. If it counts, the alert fires for a validator that works
// as configured.
func TestClaimableCountsOnlyClaimedSources(t *testing.T) {
	f := newFixture(t)
	no := false
	f.cl.cfg.Validators[0].ClaimCommission = &no
	f.chain.snap.SelfRewards = math.NewInt(500_000) // below min_claim
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	val := f.cl.cfg.Validators[0].OperatorAddress
	if got := testutil.ToFloat64(f.m.ClaimableRewards.WithLabelValues(val)); got != 500_000 {
		t.Fatalf("claimable = %v, want only self-delegation rewards", got)
	}
	if got := testutil.ToFloat64(f.m.MinClaim.WithLabelValues(val)); got != 1_000_000 {
		t.Fatalf("min_claim = %v", got)
	}
}

// withRestake sets restake on the validator of f, and makes a new Claimer
// for the changed config.
func (f *fixture) withRestake(t *testing.T) {
	t.Helper()
	f.cl.cfg.Validators[0].Restake = true
	f.cl.cfg.Validators[0].MinRestake = 1_000_000
	if err := f.cl.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	f.cl = New(f.cl.cfg, f.chain, f.secrets, f.m, f.cl.log)
	f.cl.now = func() time.Time { return f.now }
	f.cl.jitter = func(time.Duration) time.Duration { return 0 }
}

// noRewards sets the pending rewards to 0. Then the claim is below the
// threshold, and the restake can run in the same poll.
func (f *fixture) noRewards() {
	f.chain.snap.Commission = math.ZeroInt()
	f.chain.snap.SelfRewards = math.ZeroInt()
}

// delegateGrant gives the grantee a delegate grant for vals.
func (f *fixture) delegateGrant(t *testing.T, maxTokens *sdk.Coin, vals ...string) {
	t.Helper()
	var allow []sdk.ValAddress
	for _, v := range vals {
		a, err := sdk.ValAddressFromBech32(v)
		if err != nil {
			t.Fatal(err)
		}
		allow = append(allow, a)
	}
	sa, err := stakingtypes.NewStakeAuthorization(allow, nil, stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE, maxTokens)
	if err != nil {
		t.Fatal(err)
	}
	f.chain.snap.Grants[msgTypeDelegate] = chain.Grant{Authorization: sa}
}

func (f *fixture) restakeAttempts(result string) float64 {
	return testutil.ToFloat64(f.m.RestakeAttempts.WithLabelValues(f.cl.cfg.Validators[0].OperatorAddress, result))
}

// lastDelegate returns the MsgDelegate of the last tx, also if it is in a
// MsgExec.
func (f *fixture) lastDelegate(t *testing.T) *stakingtypes.MsgDelegate {
	t.Helper()
	msgs := f.chain.lastTx.Msgs
	if exec, ok := msgs[0].(*authz.MsgExec); ok {
		var err error
		if msgs, err = exec.GetMessages(); err != nil {
			t.Fatal(err)
		}
	}
	d, ok := msgs[0].(*stakingtypes.MsgDelegate)
	if len(msgs) != 1 || !ok {
		t.Fatalf("last tx msgs = %v, want one MsgDelegate", msgs)
	}
	return d
}

// TestRestakeKeepsReserveAndFee checks the amount when the operator signs.
// The restake keeps restake_reserve, and the operator also pays the fee.
func TestRestakeKeepsReserveAndFee(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	f.noRewards()
	ctx := context.Background()
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	val := f.cl.cfg.Validators[0].OperatorAddress
	d := f.lastDelegate(t)
	// 7_000_000 balance - 1_000_000 reserve - 600 fee
	if want := sdk.NewInt64Coin("usovr", 5_999_400); !d.Amount.Equal(want) {
		t.Fatalf("delegated %s, want %s", d.Amount, want)
	}
	if d.DelegatorAddress != f.chain.snap.Operator.Address.String() || d.ValidatorAddress != val {
		t.Fatalf("delegation %s -> %s", d.DelegatorAddress, d.ValidatorAddress)
	}
	if got := testutil.ToFloat64(f.m.Restaked.WithLabelValues(val)); got != 5_999_400 {
		t.Fatalf("restaked = %v", got)
	}
	if got := testutil.ToFloat64(f.m.RestakeFeesPaid.WithLabelValues(val)); got != 600 {
		t.Fatalf("restake fees = %v", got)
	}
	if got := testutil.ToFloat64(f.m.FeesPaid.WithLabelValues(val)); got != 0 {
		t.Fatalf("claim fees = %v, want 0", got)
	}
	if f.restakeAttempts("success") != 1 || f.attempts("success") != 0 {
		t.Fatal("restake not recorded as a restake")
	}
	if !f.cl.restakes.sched[val].next.Equal(f.now.Add(24 * time.Hour)) {
		t.Fatal("next restake is not restake_interval from now")
	}

	f.now = f.now.Add(time.Hour)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.broadcast != 1 {
		t.Fatal("restaked before restake_interval passed")
	}
}

// TestRestakeWaitsForPollWithoutClaim checks that a poll sends one tx or
// less for each validator. The restake after a claim waits for the next
// poll, which has a new snapshot.
func TestRestakeWaitsForPollWithoutClaim(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	ctx := context.Background()
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.broadcast != 1 || len(f.chain.lastTx.Msgs) != 2 {
		t.Fatalf("broadcast=%d msgs=%d, want only the claim", f.chain.broadcast, len(f.chain.lastTx.Msgs))
	}
	for _, r := range metrics.RestakeResults {
		if f.restakeAttempts(r) != 0 {
			t.Fatalf("restake attempt %q in the poll of the claim", r)
		}
	}
	f.now = f.now.Add(5 * time.Minute)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.chain.broadcast != 2 || f.secrets.fetches != 2 {
		t.Fatalf("broadcast=%d fetches=%d, want the restake in the second poll", f.chain.broadcast, f.secrets.fetches)
	}
	f.lastDelegate(t)
}

func TestRestakeGranteeWrapsDelegate(t *testing.T) {
	f := newFixture(t)
	g := f.withGrantee(t)
	val := f.cl.cfg.Validators[0].OperatorAddress
	f.delegateGrant(t, nil, val)
	f.withRestake(t)
	f.noRewards()
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	exec, ok := f.chain.lastTx.Msgs[0].(*authz.MsgExec)
	if !ok || exec.Grantee != g.Address.String() {
		t.Fatalf("want MsgExec from grantee, got %T", f.chain.lastTx.Msgs[0])
	}
	// The grantee pays the fee. Only the reserve stays.
	if d := f.lastDelegate(t); !d.Amount.Equal(sdk.NewInt64Coin("usovr", 6_000_000)) {
		t.Fatalf("delegated %s, want 6000000usovr", d.Amount)
	}
}

func TestRestakeMaxTokensCaps(t *testing.T) {
	f := newFixture(t)
	f.withGrantee(t)
	limit := sdk.NewInt64Coin("usovr", 2_000_000)
	f.delegateGrant(t, &limit, f.cl.cfg.Validators[0].OperatorAddress)
	f.withRestake(t)
	f.noRewards()
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if d := f.lastDelegate(t); !d.Amount.Equal(limit) {
		t.Fatalf("delegated %s, want %s", d.Amount, limit)
	}
}

// TestRestakeRefusals checks each condition that stops a restake before
// the claimer gets the key.
func TestRestakeRefusals(t *testing.T) {
	other := sdk.ValAddress(secp256k1.GenPrivKey().PubKey().Address()).String()
	for name, tc := range map[string]struct {
		grantee bool
		mutate  func(*fixture, *testing.T)
		result  string
		isErr   bool
	}{
		"below min_restake":     {false, func(f *fixture, _ *testing.T) { f.chain.snap.Operator.Balance = math.NewInt(1_500_000) }, "below_threshold", false},
		"balance below reserve": {false, func(f *fixture, _ *testing.T) { f.chain.snap.Operator.Balance = math.NewInt(500_000) }, "below_threshold", false},
		"jailed":                {false, func(f *fixture, _ *testing.T) { f.chain.snap.Jailed = true }, "validator_not_bonded", false},
		"not bonded":            {false, func(f *fixture, _ *testing.T) { f.chain.snap.Bonded = false }, "validator_not_bonded", false},
		"withdraw elsewhere": {false, func(f *fixture, _ *testing.T) {
			f.chain.snap.WithdrawAddress = sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
		}, "withdraw_address_mismatch", true},
		"withdraw query failed": {false, func(f *fixture, _ *testing.T) {
			f.chain.snap.WithdrawAddress, f.chain.snap.WithdrawAddressErr = nil, errors.New("unavailable")
		}, "failed", true},
		"no delegate grant": {true, func(*fixture, *testing.T) {}, "no_grant", true},
		"generic grant": {true, func(f *fixture, _ *testing.T) {
			f.chain.snap.Grants[msgTypeDelegate] = chain.Grant{Authorization: authz.NewGenericAuthorization(msgTypeDelegate)}
		}, "no_grant", true},
		"other validator": {true, func(f *fixture, t *testing.T) { f.delegateGrant(t, nil, other) }, "no_grant", true},
		"two validators": {true, func(f *fixture, t *testing.T) {
			f.delegateGrant(t, nil, f.cl.cfg.Validators[0].OperatorAddress, other)
		}, "no_grant", true},
		"deny list": {true, func(f *fixture, t *testing.T) {
			o, _ := sdk.ValAddressFromBech32(other)
			sa, err := stakingtypes.NewStakeAuthorization(nil, []sdk.ValAddress{o}, stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.chain.snap.Grants[msgTypeDelegate] = chain.Grant{Authorization: sa}
		}, "no_grant", true},
		// The remaining limit of the grant is less than min_restake. Each
		// later restake would stop at the limit. Thus, it is a failure.
		"grant limit": {true, func(f *fixture, t *testing.T) {
			limit := sdk.NewInt64Coin("usovr", 500_000)
			f.delegateGrant(t, &limit, f.cl.cfg.Validators[0].OperatorAddress)
		}, "grant_limit", true},
		// The balance is less than min_restake also without the limit. This
		// is a skip, not a grant_limit failure.
		"grant limit and low balance": {true, func(f *fixture, t *testing.T) {
			limit := sdk.NewInt64Coin("usovr", 500_000)
			f.delegateGrant(t, &limit, f.cl.cfg.Validators[0].OperatorAddress)
			f.chain.snap.Operator.Balance = math.NewInt(1_500_000)
		}, "below_threshold", false},
		// The node sent max_tokens without an amount. The claimer must
		// return an error, not panic.
		"max_tokens without amount": {true, func(f *fixture, t *testing.T) {
			f.delegateGrant(t, nil, f.cl.cfg.Validators[0].OperatorAddress)
			sa := f.chain.snap.Grants[msgTypeDelegate].Authorization.(*stakingtypes.StakeAuthorization)
			sa.MaxTokens = &sdk.Coin{Denom: "usovr"}
		}, "no_grant", true},
		"expiring grant": {true, func(f *fixture, t *testing.T) {
			f.delegateGrant(t, nil, f.cl.cfg.Validators[0].OperatorAddress)
			g := f.chain.snap.Grants[msgTypeDelegate]
			soon := f.chain.snap.BlockTime.Add(30 * time.Second) // before tx_timeout
			g.Expiry = &soon
			f.chain.snap.Grants[msgTypeDelegate] = g
		}, "no_grant", true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if tc.grantee {
				f.withGrantee(t)
			}
			f.withRestake(t)
			f.noRewards()
			tc.mutate(f, t)
			err := f.cl.Poll(context.Background(), ModeScheduled)
			if (err != nil) != tc.isErr {
				t.Fatalf("err = %v, want error %v", err, tc.isErr)
			}
			if f.restakeAttempts(tc.result) != 1 {
				t.Fatalf("restake_attempts{result=%q} not counted", tc.result)
			}
			if f.secrets.fetches != 0 || f.chain.broadcast != 0 {
				t.Fatal("fetched the secret or broadcast")
			}
			val := f.cl.cfg.Validators[0].OperatorAddress
			want := 0.0
			if tc.isErr {
				want = 1
			}
			if got := testutil.ToFloat64(f.m.RestakeFailures.WithLabelValues(val)); got != want {
				t.Fatalf("restake failures = %v, want %v", got, want)
			}
			if got := testutil.ToFloat64(f.m.ClaimFailures.WithLabelValues(val)); got != 0 {
				t.Fatalf("claim failures = %v, want 0", got)
			}
			if tc.result == "withdraw_address_mismatch" {
				if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, "withdraw_address")); got != 1 {
					t.Fatalf("errors{stage=withdraw_address} = %v, want 1", got)
				}
			}
			if tc.result == "failed" {
				if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, "query")); got != 1 {
					t.Fatalf("errors{stage=query} = %v, want 1", got)
				}
			}
			if tc.result == "grant_limit" || tc.result == "no_grant" {
				if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, "grant")); got != 1 {
					t.Fatalf("errors{stage=grant} = %v, want 1", got)
				}
			}
			if tc.result == "grant_limit" {
				// The no-restake alert must not fire. The failing alert shows
				// this fault.
				if got := testutil.ToFloat64(f.m.Restakeable.WithLabelValues(val)); got != 0 {
					t.Fatalf("restakeable = %v, want 0", got)
				}
			}
		})
	}
}

func TestRestakeDryRun(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	f.noRewards()
	if err := f.cl.Poll(context.Background(), ModeDryRun); err != nil {
		t.Fatal(err)
	}
	if f.restakeAttempts("dry_run") != 1 || f.secrets.fetches != 0 || f.chain.broadcast != 0 {
		t.Fatal("dry run restake fetched the secret, broadcast, or was not counted")
	}
}

// TestRestakeableGauge checks the gauge that the no-restake alert compares
// with min_restake.
func TestRestakeableGauge(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	val := f.cl.cfg.Validators[0].OperatorAddress
	gauge := func() float64 { return testutil.ToFloat64(f.m.Restakeable.WithLabelValues(val)) }
	_ = f.cl.Poll(context.Background(), ModeDryRun)
	// 7_000_000 balance - 1_000_000 reserve - 50_000 max_fee
	if gauge() != 5_950_000 {
		t.Fatalf("restakeable = %v", gauge())
	}
	// A jailed validator has its own alert. The no-restake alert must not
	// also fire.
	f.chain.snap.Jailed = true
	_ = f.cl.Poll(context.Background(), ModeDryRun)
	if gauge() != 0 {
		t.Fatalf("restakeable = %v for a jailed validator, want 0", gauge())
	}
}

// TestRestakeableGaugeExpiringGrant checks that the gauge is 0 when the
// delegate grant expires before the restake can be in a block. The grant
// expiry alert shows this fault. The no-restake alert must not also fire.
func TestRestakeableGaugeExpiringGrant(t *testing.T) {
	f := newFixture(t)
	f.withGrantee(t)
	val := f.cl.cfg.Validators[0].OperatorAddress
	f.delegateGrant(t, nil, val)
	f.withRestake(t)
	gauge := func() float64 { return testutil.ToFloat64(f.m.Restakeable.WithLabelValues(val)) }
	_ = f.cl.Poll(context.Background(), ModeDryRun)
	// 7_000_000 balance - 1_000_000 reserve; the grantee pays the fee
	if gauge() != 6_000_000 {
		t.Fatalf("restakeable = %v", gauge())
	}
	g := f.chain.snap.Grants[msgTypeDelegate]
	soon := f.chain.snap.BlockTime.Add(30 * time.Second) // before tx_timeout
	g.Expiry = &soon
	f.chain.snap.Grants[msgTypeDelegate] = g
	_ = f.cl.Poll(context.Background(), ModeDryRun)
	if gauge() != 0 {
		t.Fatalf("restakeable = %v for an expiring delegate grant, want 0", gauge())
	}
}

// TestRestakeLateConfirmation checks that a late restake tx is recorded as
// a restake, not as a claim.
func TestRestakeLateConfirmation(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	f.noRewards()
	ctx := context.Background()
	val := f.cl.cfg.Validators[0].OperatorAddress
	f.chain.txErr = context.DeadlineExceeded
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	f.chain.txErr = nil
	f.now = f.now.Add(time.Minute)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(f.m.Restaked.WithLabelValues(val)); got != 5_999_400 {
		t.Fatalf("restaked = %v", got)
	}
	if got := testutil.ToFloat64(f.m.Claimed.WithLabelValues(val, SourceCommission)); got != 0 {
		t.Fatalf("late restake recorded as a claim of %v", got)
	}
	if f.restakeAttempts("success") != 1 || f.attempts("success") != 0 || f.chain.broadcast != 1 {
		t.Fatal("late restake not recorded once as a restake")
	}
}

// TestWithdrawAddressOnlyForRestake checks that the claimer asks for the
// withdraw address only for a validator with restake. Without restake, a
// fault in this query must not stop the claims.
func TestWithdrawAddressOnlyForRestake(t *testing.T) {
	f := newFixture(t)
	f.noRewards()
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	f.withRestake(t)
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if got := f.chain.withdrawQueries; len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("withdraw address queries = %v, want [false true]", got)
	}
}

// TestWithdrawQueryFailureAllowsClaim checks that a failed withdraw
// address query does not stop a claim that is due.
func TestWithdrawQueryFailureAllowsClaim(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	f.chain.snap.WithdrawAddress, f.chain.snap.WithdrawAddressErr = nil, errors.New("unavailable")
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if f.attempts("success") != 1 || f.chain.broadcast != 1 {
		t.Fatal("claim did not run")
	}
	val := f.cl.cfg.Validators[0].OperatorAddress
	if got := testutil.ToFloat64(f.m.Errors.WithLabelValues(val, "query")); got != 0 {
		t.Fatalf("errors{stage=query} = %v, want 0", got)
	}
}

// TestRestakeRefusesNilWithdrawAddress checks that a snapshot without the
// withdraw address stops the restake.
func TestRestakeRefusesNilWithdrawAddress(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	s := f.chain.snap
	s.WithdrawAddress = nil
	if _, result, err := f.cl.planRestake(f.cl.cfg.Validators[0], &s, math.NewInt(f.cl.cfg.MaxFee)); result != "withdraw_address_mismatch" || err == nil {
		t.Fatalf("result = %q, err = %v; want withdraw_address_mismatch", result, err)
	}
}

// TestConfirmLogKeys checks the keys of the confirmation logs. The claim
// keeps the keys from before the restake: pending and next_claim.
func TestConfirmLogKeys(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	var buf bytes.Buffer
	f.cl.log = slog.New(slog.NewJSONHandler(&buf, nil))
	confirmLine := func(msg string) map[string]any {
		t.Helper()
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var rec map[string]any
			if err := json.Unmarshal([]byte(l), &rec); err != nil {
				t.Fatal(err)
			}
			if rec["msg"] == msg {
				return rec
			}
		}
		t.Fatalf("no %q log in %s", msg, buf.String())
		return nil
	}
	ctx := context.Background()
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	f.noRewards()
	f.now = f.now.Add(5 * time.Minute)
	if err := f.cl.Poll(ctx, ModeScheduled); err != nil {
		t.Fatal(err)
	}
	for msg, keys := range map[string][]string{
		"claim confirmed":   {"pending", "next_claim", SourceCommission, SourceSelfDelegation},
		"restake confirmed": {"amount", "next_restake"},
	} {
		rec := confirmLine(msg)
		for _, k := range keys {
			if _, ok := rec[k]; !ok {
				t.Errorf("%q log has no %q key: %v", msg, k, rec)
			}
		}
	}
}

// TestRestakeIntervalGauge checks the gauge that the no-restake alert uses
// for its time window.
func TestRestakeIntervalGauge(t *testing.T) {
	f := newFixture(t)
	f.withRestake(t)
	val := f.cl.cfg.Validators[0].OperatorAddress
	if got := testutil.ToFloat64(f.m.RestakeInterval.WithLabelValues(val)); got != 86400 {
		t.Fatalf("restake_interval_seconds = %v, want 86400", got)
	}
}

func TestRestakeOffHasNoRestakeSeries(t *testing.T) {
	f := newFixture(t)
	f.noRewards()
	if err := f.cl.Poll(context.Background(), ModeScheduled); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(f.m.RestakeAttempts); n != 0 {
		t.Fatalf("restake_attempts_total has %d series without restake", n)
	}
	if f.chain.broadcast != 0 {
		t.Fatal("sent a tx without restake")
	}
}
