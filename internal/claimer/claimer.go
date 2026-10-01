// Package claimer decides when to withdraw x/distribution rewards for each
// configured validator, and sends the claim.
//
// All steps up to and including the gas simulation use only public data. The
// claimer gets the signing mnemonic from the secret provider only after it
// knows that the claim is worth the fee. It writes zeros over the derived key
// immediately after it signs.
//
// The signer is the operator account. If a validator has a grantee_address,
// the signer is an authz grantee that sends the withdrawals in a MsgExec.
//
// If a validator has restake set, the claimer also delegates the spendable
// balance of the operator account to the validator, on a separate schedule.
// The restake keeps restake_reserve in the account for fees.
package claimer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	stdmath "math"
	"math/rand/v2"
	"time"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sovrn-tech/sovr-harvest/internal/chain"
	"github.com/sovrn-tech/sovr-harvest/internal/config"
	"github.com/sovrn-tech/sovr-harvest/internal/metrics"
	"github.com/sovrn-tech/sovr-harvest/internal/secret"
	"github.com/sovrn-tech/sovr-harvest/internal/signer"
)

// Chain is the part of *chain.Client that the claimer uses.
type Chain interface {
	Snapshot(ctx context.Context, valoper sdk.ValAddress, denom string, grantee sdk.AccAddress, withdraw bool) (*chain.Snapshot, error)
	Simulate(ctx context.Context, tx chain.Tx, pub cryptotypes.PubKey, seq uint64) (uint64, error)
	Sign(ctx context.Context, tx chain.Tx, priv cryptotypes.PrivKey, chainID string, accNum, seq uint64) ([]byte, error)
	Broadcast(ctx context.Context, txBytes []byte) (string, error)
	WaitTx(ctx context.Context, hash string) (*sdk.TxResponse, error)
}

const (
	SourceCommission     = "commission"
	SourceSelfDelegation = "self_delegation"

	retryBase = 5 * time.Minute
	retryMax  = 6 * time.Hour

	// pollSlack is the time limit for the queries, simulation, secret fetch,
	// and broadcast of one validator. The confirmation gets tx_timeout in
	// addition to it.
	pollSlack = 2 * time.Minute

	// maxSimGas is the maximum gas that the claimer accepts from a simulation.
	// A claim uses approximately 150k gas. The claimer does not trust the node.
	// A very large value would overflow the gas limit and fee arithmetic.
	maxSimGas = 5_000_000

	// If the confirmation of a claim tx times out, the next polls look for the
	// tx again. Each lookup has the time limit lateCheckTimeout. The polls stop
	// when they find the tx, or when lateGiveUp has passed since the claimer
	// sent it.
	lateCheckTimeout = 10 * time.Second
	lateGiveUp       = time.Hour
)

type Claimer struct {
	cfg     *config.Config
	chain   Chain
	secrets secret.Provider
	m       *metrics.Metrics
	log     *slog.Logger

	now      func() time.Time
	jitter   func(max time.Duration) time.Duration
	claims   *action
	restakes *action
	// unconfirmed holds, for each validator, a tx that the claimer broadcast,
	// but that was not in a block before tx_timeout. It can still get into a
	// block. Thus, the claimer sends no new tx for that validator until it
	// finds this tx or stops the search. A new tx would use the same sequence,
	// and only one of the two txs could get into a block.
	unconfirmed map[string]*sentTx
}

// action is one type of tx that the claimer sends for a validator. Each
// action has its own schedule, backoff, and metrics.
type action struct {
	name     string
	valueKey string // the log key of the value of a tx
	interval time.Duration
	attempts *prometheus.CounterVec // validator, result
	failures *prometheus.GaugeVec   // validator
	fees     *prometheus.CounterVec // validator
	nextTime *prometheus.GaugeVec   // validator
	sched    map[string]*schedule   // by validator
	// record updates the metrics for a confirmed tx of this action. It
	// returns the log attributes of the result, other than the value.
	record func(val string, res *sdk.TxResponse, value math.Int) []any
}

type schedule struct {
	next     time.Time // earliest time for the next tx
	failures int
}

type sentTx struct {
	a     *action
	hash  string
	fee   math.Int
	value math.Int // the value of the tx for a.record
	sent  time.Time
}

func New(cfg *config.Config, c Chain, s secret.Provider, m *metrics.Metrics, log *slog.Logger) *Claimer {
	cl := &Claimer{
		cfg: cfg, chain: c, secrets: s, m: m, log: log,
		now: time.Now,
		jitter: func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return rand.N(max)
		},
		unconfirmed: map[string]*sentTx{},
	}
	cl.claims = &action{
		name: "claim", valueKey: "pending", interval: cfg.ClaimInterval.Duration,
		attempts: m.ClaimAttempts, failures: m.ClaimFailures, fees: m.FeesPaid, nextTime: m.NextClaim,
		sched: map[string]*schedule{}, record: cl.recordClaim,
	}
	cl.restakes = &action{
		name: "restake", valueKey: "amount", interval: cfg.RestakeInterval.Duration,
		attempts: m.RestakeAttempts, failures: m.RestakeFailures, fees: m.RestakeFeesPaid, nextTime: m.NextRestake,
		sched: map[string]*schedule{}, record: cl.recordRestake,
	}
	for _, v := range cfg.Validators {
		cl.claims.sched[v.OperatorAddress] = &schedule{}
		m.InitValidator(v.OperatorAddress, []string{SourceCommission, SourceSelfDelegation})
		m.MinClaim.WithLabelValues(v.OperatorAddress).Set(float64(v.MinClaim))
		if v.Restake {
			cl.restakes.sched[v.OperatorAddress] = &schedule{}
			m.InitRestake(v.OperatorAddress)
			m.MinRestake.WithLabelValues(v.OperatorAddress).Set(metrics.Float(v.MinRestakeInt()))
			m.RestakeInterval.WithLabelValues(v.OperatorAddress).Set(cfg.RestakeInterval.Seconds())
		}
	}
	return cl
}

// MaxPollDuration is the maximum duration of one Poll: the sum of the
// deadlines of all validators.
func (c *Claimer) MaxPollDuration() time.Duration {
	return time.Duration(len(c.cfg.Validators)) * (c.cfg.TxTimeout.Duration + pollSlack)
}

// Mode sets which steps one Poll does.
type Mode int

const (
	// ModeScheduled claims only when the validator is due and the rewards are
	// at the threshold or more.
	ModeScheduled Mode = iota
	// ModeForce does not use the schedule. It still applies the threshold and
	// the fee limits.
	ModeForce
	// ModeDryRun queries and simulates only. It does not use key material.
	ModeDryRun
)

// Poll updates the metrics for each validator, and claims for the validators
// that are due. Each validator has its own deadline. Thus, a slow claim for
// one validator does not stop the claim for the next. Poll returns the
// joined errors of all validators.
//
// A poll during a backoff returns nil. If a claim continues to fail,
// claim_consecutive_failures shows it, not last_successful_poll. Thus, one
// fault fires one alert.
func (c *Claimer) Poll(ctx context.Context, mode Mode) error {
	var errs []error
	for _, v := range c.cfg.Validators {
		vctx, cancel := context.WithTimeout(ctx, c.cfg.TxTimeout.Duration+pollSlack)
		err := c.pollOne(vctx, v, mode)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", v.OperatorAddress, err))
		}
	}
	now := c.now()
	c.m.LastPoll.Set(float64(now.Unix()))
	if len(errs) > 0 {
		c.m.Polls.WithLabelValues("error").Inc()
		return errors.Join(errs...)
	}
	c.m.Polls.WithLabelValues("ok").Inc()
	c.m.LastPollOK.Set(float64(now.Unix()))
	return nil
}

func (c *Claimer) pollOne(ctx context.Context, v config.Validator, mode Mode) error {
	val := v.OperatorAddress
	valoper, err := sdk.ValAddressFromBech32(val)
	if err != nil {
		return err
	}
	// Find the result of an earlier timed-out tx before the snapshot. If that
	// tx is now in a block, the claimer must not send a retry with the same
	// sequence.
	var lateErr error
	if u := c.unconfirmed[val]; u != nil {
		if lateErr = c.resolveUnconfirmed(ctx, val); lateErr != nil {
			c.backOff(u.a, val)
		}
	}

	// Only a restake uses the withdraw address. A fault in this query must
	// not stop the claims. Snapshot thus keeps that error in the snapshot,
	// and only the restake fails.
	snap, err := c.chain.Snapshot(ctx, valoper, c.cfg.Denom, v.Grantee(), v.Restake)
	if err != nil {
		c.m.Errors.WithLabelValues(val, "query").Inc()
		return errors.Join(lateErr, err)
	}
	if snap.ChainID != c.cfg.ChainID {
		c.m.Errors.WithLabelValues(val, "query").Inc()
		return errors.Join(lateErr, fmt.Errorf("node is on chain %q, config expects %q", snap.ChainID, c.cfg.ChainID))
	}
	c.observe(v, snap)

	switch {
	case lateErr != nil:
		return lateErr
	case c.unconfirmed[val] != nil:
		return nil // not in a block yet
	}
	sent, err := c.run(ctx, c.claims, v, snap, mode, c.claim)
	if sent || !v.Restake {
		return err
	}
	// Send one tx or less for each validator in each poll. A restake after a
	// claim would need a new snapshot and a second secret fetch. Also, the
	// deadline of the validator has time for only one confirmation. Thus, the
	// restake waits for a poll in which the claimer sends no claim.
	_, err = c.run(ctx, c.restakes, v, snap, mode, c.restake)
	return err
}

// run calls send for a if a is due. It reports if send sent a tx or tried
// to send one.
func (c *Claimer) run(ctx context.Context, a *action, v config.Validator, s *chain.Snapshot, mode Mode,
	send func(context.Context, config.Validator, *chain.Snapshot, bool) error) (bool, error) {
	val := v.OperatorAddress
	if mode == ModeScheduled && c.now().Before(a.sched[val].next) {
		return false, nil
	}
	err := send(ctx, v, s, mode == ModeDryRun)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errSkip):
		// The claimer sent nothing, so no tx fails. Without this reset,
		// failures would stay above 0 until the next successful tx if skips
		// come after a failure. For example, a person claims the rewards
		// manually, and the rewards are then less than min_claim.
		c.setFailures(a, val, 0)
		return false, nil
	default:
		c.backOff(a, val)
		return true, err
	}
}

// backOff records one more failed tx of a for val, and sets a later time
// for its next tx.
func (c *Claimer) backOff(a *action, val string) {
	st := a.sched[val]
	c.setFailures(a, val, st.failures+1)
	st.next = c.now().Add(backoff(st.failures))
	a.nextTime.WithLabelValues(val).Set(float64(st.next.Unix()))
}

func (c *Claimer) setFailures(a *action, val string, n int) {
	a.sched[val].failures = n
	a.failures.WithLabelValues(val).Set(float64(n))
}

func (c *Claimer) observe(v config.Validator, s *chain.Snapshot) {
	val := v.OperatorAddress
	c.m.ChainHeight.Set(float64(s.Height))
	c.m.PendingRewards.WithLabelValues(val, SourceCommission).Set(metrics.Float(s.Commission))
	c.m.PendingRewards.WithLabelValues(val, SourceSelfDelegation).Set(metrics.Float(s.SelfRewards))
	_, claimable := Plan(v, s)
	c.m.ClaimableRewards.WithLabelValues(val).Set(metrics.Float(claimable))
	c.m.OutstandingRewards.WithLabelValues(val).Set(metrics.Float(s.Outstanding))
	c.m.ValidatorBonded.WithLabelValues(val).Set(metrics.Bool(s.Bonded))
	c.m.ValidatorJailed.WithLabelValues(val).Set(metrics.Bool(s.Jailed))
	c.m.ValidatorTokens.WithLabelValues(val).Set(metrics.Float(s.Tokens))
	from := s.Signer()
	c.m.AccountBalance.WithLabelValues(val, from.Address.String(), "signer").Set(metrics.Float(from.Balance))
	if s.Grantee != nil {
		c.m.AccountBalance.WithLabelValues(val, s.Operator.Address.String(), "operator").Set(metrics.Float(s.Operator.Balance))
		for _, typ := range wantedMsgTypes(v) {
			g, ok := s.Grants[typ]
			switch {
			case !ok:
				c.m.GrantExpiry.WithLabelValues(val, typ).Set(0)
			case g.Expiry == nil:
				c.m.GrantExpiry.WithLabelValues(val, typ).Set(stdmath.Inf(1))
			default:
				c.m.GrantExpiry.WithLabelValues(val, typ).Set(float64(g.Expiry.Unix()))
			}
		}
	}
	c.observeNext(c.claims, val)
	if v.Restake {
		amt, result, _ := c.planRestake(v, s, math.NewInt(c.cfg.MaxFee))
		if result != "" && result != "below_threshold" {
			amt = math.ZeroInt()
		}
		c.m.Restakeable.WithLabelValues(val).Set(metrics.Float(math.MaxInt(amt, math.ZeroInt())))
		c.observeNext(c.restakes, val)
	}
}

func (c *Claimer) observeNext(a *action, val string) {
	next := a.sched[val].next
	if next.IsZero() {
		next = c.now() // this process did not send this tx before, so it is due now
	}
	a.nextTime.WithLabelValues(val).Set(float64(next.Unix()))
}

// errSkip marks a tx that the claimer did not send on purpose. It is not
// a failure.
var errSkip = errors.New("skipped")

var (
	msgTypeCommission     = sdk.MsgTypeURL(&distrtypes.MsgWithdrawValidatorCommission{})
	msgTypeSelfDelegation = sdk.MsgTypeURL(&distrtypes.MsgWithdrawDelegatorReward{})
	msgTypeDelegate       = sdk.MsgTypeURL(&stakingtypes.MsgDelegate{})
)

// wantedMsgTypes lists the msg types that v sends. The grantee must have a
// grant for each of these types.
func wantedMsgTypes(v config.Validator) []string {
	var out []string
	if v.WantCommission() {
		out = append(out, msgTypeCommission)
	}
	if v.WantSelfDelegation() {
		out = append(out, msgTypeSelfDelegation)
	}
	if v.Restake {
		out = append(out, msgTypeDelegate)
	}
	return out
}

// Plan lists the withdraw messages to send for s, and their total.
func Plan(v config.Validator, s *chain.Snapshot) ([]sdk.Msg, math.Int) {
	var msgs []sdk.Msg
	total := math.ZeroInt()
	if v.WantCommission() && s.Commission.IsPositive() {
		msgs = append(msgs, &distrtypes.MsgWithdrawValidatorCommission{ValidatorAddress: v.OperatorAddress})
		total = total.Add(s.Commission)
	}
	if v.WantSelfDelegation() && s.SelfRewards.IsPositive() {
		msgs = append(msgs, &distrtypes.MsgWithdrawDelegatorReward{
			DelegatorAddress: s.Operator.Address.String(),
			ValidatorAddress: v.OperatorAddress,
		})
		total = total.Add(s.SelfRewards)
	}
	return msgs, total
}

func (c *Claimer) claim(ctx context.Context, v config.Validator, s *chain.Snapshot, dryRun bool) error {
	msgs, total := Plan(v, s)
	if len(msgs) == 0 || total.LT(v.MinClaimInt()) {
		c.claims.attempts.WithLabelValues(v.OperatorAddress, "below_threshold").Inc()
		c.log.Info("pending rewards below min_claim", "validator", v.OperatorAddress, "height", s.Height,
			"pending", total.String(), "min_claim", v.MinClaim)
		return errSkip
	}
	return c.send(ctx, c.claims, v, s, dryRun, func(math.Int) ([]sdk.Msg, math.Int) { return msgs, total })
}

// restake delegates the spendable balance of the operator account, minus
// restake_reserve, to the validator.
func (c *Claimer) restake(ctx context.Context, v config.Validator, s *chain.Snapshot, dryRun bool) error {
	val := v.OperatorAddress
	_, result, err := c.planRestake(v, s, math.NewInt(c.cfg.MaxFee))
	switch result {
	case "":
	case "below_threshold", "validator_not_bonded":
		c.restakes.attempts.WithLabelValues(val, result).Inc()
		c.log.Info("restake skipped", "validator", val, "height", s.Height, "result", result, "reason", err)
		return errSkip
	case "no_grant", "grant_limit":
		c.restakes.attempts.WithLabelValues(val, result).Inc()
		c.m.Errors.WithLabelValues(val, "grant").Inc()
		return err
	case "failed":
		c.restakes.attempts.WithLabelValues(val, result).Inc()
		c.m.Errors.WithLabelValues(val, "query").Inc()
		return err
	case "withdraw_address_mismatch":
		c.restakes.attempts.WithLabelValues(val, result).Inc()
		c.m.Errors.WithLabelValues(val, "withdraw_address").Inc()
		return err
	default:
		c.restakes.attempts.WithLabelValues(val, result).Inc()
		return err
	}
	return c.send(ctx, c.restakes, v, s, dryRun, func(fee math.Int) ([]sdk.Msg, math.Int) {
		amt := c.restakeAmount(v, s, fee)
		return []sdk.Msg{&stakingtypes.MsgDelegate{
			DelegatorAddress: s.Operator.Address.String(),
			ValidatorAddress: val,
			Amount:           sdk.NewCoin(c.cfg.Denom, amt),
		}}, amt
	})
}

// planRestake returns the amount that a restake for v can delegate if its
// fee is fee. If the restake cannot run, planRestake also returns the
// attempt result and the reason. For below_threshold, it returns the
// amount.
//
// If only the max_tokens of the delegate grant makes the amount less than
// min_restake, the result is grant_limit, not below_threshold. The
// remaining limit is then too small for each later restake. The balance
// stays liquid until the operator gives a new grant. Thus, this result is
// a failure, not a skip.
func (c *Claimer) planRestake(v config.Validator, s *chain.Snapshot, fee math.Int) (math.Int, string, error) {
	val := v.OperatorAddress
	zero := math.ZeroInt()
	if s.WithdrawAddressErr != nil {
		return zero, "failed", s.WithdrawAddressErr
	}
	if s.WithdrawAddress == nil || !s.WithdrawAddress.Equals(s.Operator.Address) {
		// The rewards do not go to the operator account, or the snapshot
		// does not have the withdraw address. A restake would delegate
		// funds that are not rewards.
		return zero, "withdraw_address_mismatch", fmt.Errorf("withdraw address of %s is %s; restake needs the rewards in the operator account",
			s.Operator.Address, s.WithdrawAddress)
	}
	if !s.Bonded || s.Jailed {
		return zero, "validator_not_bonded", errors.New("validator is not bonded or is jailed")
	}
	if s.Grantee != nil {
		if err := checkDelegateGrant(val, c.cfg.Denom, s, s.BlockTime.Add(c.cfg.TxTimeout.Duration)); err != nil {
			return zero, "no_grant", err
		}
	}
	amt := c.restakeAmount(v, s, fee)
	if !amt.IsPositive() || amt.LT(v.MinRestakeInt()) {
		if lim, ok := delegateLimit(s); ok && restakeBalance(v, s, fee).GTE(v.MinRestakeInt()) {
			return zero, "grant_limit", fmt.Errorf("delegate grant max_tokens %s%s is less than min_restake %d; give a new delegate grant",
				lim, c.cfg.Denom, v.MinRestake)
		}
		return amt, "below_threshold", fmt.Errorf("restakeable %s is less than min_restake %d", amt, v.MinRestake)
	}
	return amt, "", nil
}

// restakeAmount is restakeBalance, but not more than the max_tokens of the
// delegate grant.
func (c *Claimer) restakeAmount(v config.Validator, s *chain.Snapshot, fee math.Int) math.Int {
	amt := restakeBalance(v, s, fee)
	if lim, ok := delegateLimit(s); ok {
		amt = math.MinInt(amt, lim)
	}
	return amt
}

// restakeBalance is the operator balance minus restake_reserve. If the
// operator signs, the operator also pays fee.
func restakeBalance(v config.Validator, s *chain.Snapshot, fee math.Int) math.Int {
	amt := s.Operator.Balance.Sub(v.Reserve())
	if s.Grantee == nil {
		amt = amt.Sub(fee)
	}
	return amt
}

// delegateLimit returns the max_tokens of the delegate grant to the
// grantee, if the grant has one.
func delegateLimit(s *chain.Snapshot) (math.Int, bool) {
	if s.Grantee == nil {
		return math.Int{}, false
	}
	sa, ok := s.Grants[msgTypeDelegate].Authorization.(*stakingtypes.StakeAuthorization)
	if !ok || sa.MaxTokens == nil {
		return math.Int{}, false
	}
	return sa.MaxTokens.Amount, true
}

// checkDelegateGrant makes sure that the delegate grant to the grantee is a
// StakeAuthorization that allows delegations only to val. A generic grant,
// or a grant for other validators, lets a person with the grantee key bond
// the operator funds to a validator of that person. That validator can then
// be slashed.
//
// The grant must also not expire before deadline. send does the same check,
// but the restakeable gauge uses only this function. Without this check, the
// gauge would show an amount for a restake that fails.
func checkDelegateGrant(val, denom string, s *chain.Snapshot, deadline time.Time) error {
	g, ok := s.Grants[msgTypeDelegate]
	if !ok || (g.Expiry != nil && !g.Expiry.After(deadline)) {
		return fmt.Errorf("no unexpired authz grant from %s to %s for %s", s.Operator.Address, s.Grantee.Address, msgTypeDelegate)
	}
	sa, ok := g.Authorization.(*stakingtypes.StakeAuthorization)
	if !ok {
		return fmt.Errorf("delegate grant from %s to %s is %T; use a StakeAuthorization with --allowed-validators %s",
			s.Operator.Address, s.Grantee.Address, g.Authorization, val)
	}
	allow := sa.GetAllowList().GetAddress()
	if sa.AuthorizationType != stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE || len(allow) != 1 || allow[0] != val {
		return fmt.Errorf("delegate grant from %s to %s must allow only %s", s.Operator.Address, s.Grantee.Address, val)
	}
	if sa.MaxTokens != nil {
		// A node can send a coin without an amount. math.MinInt panics
		// on a nil amount. Thus, delegateLimit must not get such a coin.
		if err := sa.MaxTokens.Validate(); err != nil {
			return fmt.Errorf("delegate grant max_tokens is not valid: %w", err)
		}
		if sa.MaxTokens.Denom != denom {
			return fmt.Errorf("delegate grant max_tokens denom is %q, want %q", sa.MaxTokens.Denom, denom)
		}
	}
	return nil
}

// send sends one tx of a for v. mk makes the msgs for a given fee, and
// returns the value that the tx moves. The claimer does not send a tx whose
// fee is equal to or more than its value.
//
// send calls mk with max_fee for the simulation. After it knows the fee, it
// calls mk again with the fee. Only the amounts in the msgs can change
// between the two calls. Thus, the gas stays approximately the same, and
// gas_adjustment covers the difference.
//
// All steps up to and including the fee checks use only public data. send
// gets the mnemonic only after these checks pass.
func (c *Claimer) send(ctx context.Context, a *action, v config.Validator, s *chain.Snapshot, dryRun bool,
	mk func(fee math.Int) ([]sdk.Msg, math.Int)) error {
	val := v.OperatorAddress
	log := c.log.With("validator", val, "height", s.Height, "action", a.name)
	skip := func(result, msg string, args ...any) error {
		a.attempts.WithLabelValues(val, result).Inc()
		log.Info(msg, args...)
		return errSkip
	}
	// fail records a tx attempt that failed at stage.
	fail := func(stage string, err error) error {
		c.m.Errors.WithLabelValues(val, stage).Inc()
		a.attempts.WithLabelValues(val, "failed").Inc()
		return err
	}

	msgs, _ := mk(math.NewInt(c.cfg.MaxFee))
	if s.Grantee != nil {
		// Check the grants here. If the simulation fails instead, the error does
		// not tell what to repair. A grant must not expire before the tx is in a
		// block.
		deadline := s.BlockTime.Add(c.cfg.TxTimeout.Duration)
		for _, m := range msgs {
			typ := sdk.MsgTypeURL(m)
			g, ok := s.Grants[typ]
			if !ok || (g.Expiry != nil && !g.Expiry.After(deadline)) {
				a.attempts.WithLabelValues(val, "no_grant").Inc()
				c.m.Errors.WithLabelValues(val, "grant").Inc()
				return fmt.Errorf("no unexpired authz grant from %s to %s for %s", s.Operator.Address, s.Grantee.Address, typ)
			}
		}
	}
	// wrap puts the msgs in a MsgExec if the grantee signs.
	wrap := func(msgs []sdk.Msg) []sdk.Msg {
		if s.Grantee == nil {
			return msgs
		}
		exec := authz.NewMsgExec(s.Grantee.Address, msgs)
		return []sdk.Msg{&exec}
	}
	from := s.Signer()

	// The simulation needs a pubkey. After an account signs its first tx, the
	// account has a pubkey on chain. If it did not sign a tx, simulate with an
	// empty secp256k1 placeholder, as the SDK client does. In simulate mode,
	// the ante handler does not do the pubkey/address check, and it charges
	// secp256k1 gas.
	var simPub cryptotypes.PubKey = &secp256k1.PubKey{}
	if from.PubKey != nil {
		simPub = from.PubKey
	}

	tx := chain.Tx{Msgs: wrap(msgs), Memo: c.cfg.Memo}
	gasUsed, err := c.chain.Simulate(ctx, tx, simPub, from.Sequence)
	if err != nil {
		return fail("simulate", err)
	}
	if gasUsed == 0 || gasUsed > maxSimGas {
		return fail("simulate", fmt.Errorf("simulation reported implausible gas used %d", gasUsed))
	}
	// gas_adjustment is 10 or less, so this cannot overflow.
	tx.GasLimit = uint64(float64(gasUsed) * c.cfg.GasAdjustment)
	gp := c.cfg.GasPriceCoin()
	feeAmt := gp.Amount.MulInt64(int64(tx.GasLimit)).Ceil().TruncateInt()
	tx.Fee = sdk.NewCoins(sdk.NewCoin(c.cfg.Denom, feeAmt))

	if feeAmt.GT(math.NewInt(c.cfg.MaxFee)) {
		a.attempts.WithLabelValues(val, "fee_too_high").Inc()
		return fmt.Errorf("fee %s exceeds max_fee %d", feeAmt, c.cfg.MaxFee)
	}
	msgs, value := mk(feeAmt)
	tx.Msgs = wrap(msgs)
	switch {
	case feeAmt.GTE(value):
		return skip("below_threshold", "fee would eat the "+a.name, "fee", feeAmt.String(), a.valueKey, value.String())
	case from.Balance.LT(feeAmt):
		a.attempts.WithLabelValues(val, "insufficient_balance").Inc()
		return fmt.Errorf("%s balance %s cannot pay fee %s", from.Address, from.Balance, feeAmt)
	}

	log = log.With("signer", from.Address.String(), a.valueKey, value.String(), "gas_limit", tx.GasLimit, "fee", feeAmt.String())
	if dryRun {
		return skip("dry_run", "dry run: would send "+a.name)
	}

	// loadKey makes sure that the derived address is correct. Also make sure
	// that the on-chain pubkey is correct.
	key, err := c.loadKey(ctx, v, from.Address)
	if err != nil {
		return fail("secret", err)
	}
	defer key.Wipe()
	if from.PubKey != nil && !key.PubKey().Equals(from.PubKey) {
		return fail("secret", errors.New("derived pubkey does not match the pubkey on chain"))
	}
	txBytes, err := c.chain.Sign(ctx, tx, key.PrivKey(), s.ChainID, from.AccountNumber, from.Sequence)
	key.Wipe()
	if err != nil {
		return fail("sign", err)
	}

	hash, err := c.chain.Broadcast(ctx, txBytes)
	if err != nil {
		return fail("broadcast", err)
	}
	log = log.With("tx", hash)
	log.Info(a.name + " tx broadcast")

	wctx, cancel := context.WithTimeout(ctx, c.cfg.TxTimeout.Duration)
	defer cancel()
	res, err := c.chain.WaitTx(wctx, hash)
	if err != nil {
		if res == nil {
			// The tx was not in a block in time, but it can still get into one.
			// The claimer records its result when a later poll finds it or stops
			// the search.
			c.unconfirmed[val] = &sentTx{a: a, hash: hash, fee: feeAmt, value: value, sent: c.now()}
			log.Warn(a.name+" tx not confirmed within tx_timeout; will look for it on later polls", "err", err)
			return nil
		}
		// The tx is in a block, but it failed. The chain still took its fee.
		a.fees.WithLabelValues(val).Add(metrics.Float(feeAmt))
		return fail("confirm", err)
	}
	c.confirmed(a, val, res, feeAmt, value, log, a.name+" confirmed")
	return nil
}

// confirmed records a successful tx of a and schedules the next one.
func (c *Claimer) confirmed(a *action, val string, res *sdk.TxResponse, fee, value math.Int, log *slog.Logger, msg string) {
	a.fees.WithLabelValues(val).Add(metrics.Float(fee))
	a.attempts.WithLabelValues(val, "success").Inc()
	attrs := a.record(val, res, value)

	c.setFailures(a, val, 0)
	st := a.sched[val]
	st.next = c.now().Add(a.interval + c.jitter(c.cfg.ClaimJitter.Duration))
	a.nextTime.WithLabelValues(val).Set(float64(st.next.Unix()))
	log.Info(msg, append([]any{"block", res.Height, "gas_used", res.GasUsed}, append(attrs,
		"next_"+a.name, st.next.Format(time.RFC3339))...)...)
}

// recordClaim updates the claim metrics from the events of a confirmed
// claim tx.
func (c *Claimer) recordClaim(val string, res *sdk.TxResponse, _ math.Int) []any {
	claimed := ClaimedFromEvents(res, c.cfg.Denom)
	for src, amt := range claimed {
		c.m.Claimed.WithLabelValues(val, src).Add(metrics.Float(amt))
	}
	c.m.LastClaim.WithLabelValues(val).Set(float64(c.now().Unix()))
	c.m.LastClaimGas.WithLabelValues(val).Set(float64(res.GasUsed))
	return []any{
		SourceCommission, claimed[SourceCommission].String(),
		SourceSelfDelegation, claimed[SourceSelfDelegation].String(),
	}
}

// recordRestake updates the restake metrics for a confirmed restake tx of
// amount. The log already has the amount.
func (c *Claimer) recordRestake(val string, _ *sdk.TxResponse, amount math.Int) []any {
	c.m.Restaked.WithLabelValues(val).Add(metrics.Float(amount))
	c.m.LastRestake.WithLabelValues(val).Set(float64(c.now().Unix()))
	return nil
}

// resolveUnconfirmed looks for a tx whose confirmation timed out. When the
// result is known, it records the result. The result is a success if the tx
// is in a block and did not fail. The result is a failure if the tx failed,
// or if lateGiveUp passed and the tx was not found. For a failure,
// resolveUnconfirmed returns an error. While the tx is pending, it keeps
// the tx in c.unconfirmed.
func (c *Claimer) resolveUnconfirmed(ctx context.Context, val string) error {
	u := c.unconfirmed[val]
	a := u.a
	log := c.log.With("validator", val, "action", a.name, "tx", u.hash, a.valueKey, u.value.String())
	wctx, cancel := context.WithTimeout(ctx, lateCheckTimeout)
	defer cancel()
	res, err := c.chain.WaitTx(wctx, u.hash)
	fail := func(err error) error {
		delete(c.unconfirmed, val)
		c.m.Errors.WithLabelValues(val, "confirm").Inc()
		a.attempts.WithLabelValues(val, "failed").Inc()
		return err
	}
	switch {
	case res == nil && c.now().Sub(u.sent) < lateGiveUp:
		return nil
	case res == nil:
		log.Warn("giving up on unconfirmed tx", "sent", u.sent.Format(time.RFC3339))
		return fail(fmt.Errorf("%s tx %s not found within %v: %w", a.name, u.hash, lateGiveUp, err))
	case err != nil:
		a.fees.WithLabelValues(val).Add(metrics.Float(u.fee))
		log.Warn("unconfirmed tx landed but failed", "err", err)
		return fail(err)
	}
	delete(c.unconfirmed, val)
	c.confirmed(a, val, res, u.fee, u.value, log, "unconfirmed "+a.name+" tx confirmed late")
	return nil
}

func (c *Claimer) loadKey(ctx context.Context, v config.Validator, want sdk.AccAddress) (*signer.Key, error) {
	start := c.now()
	mnemonic, err := c.secrets.Fetch(ctx, v.MnemonicRef)
	c.m.SecretTime.Observe(c.now().Sub(start).Seconds())
	if err != nil {
		c.m.SecretFetch.WithLabelValues("error").Inc()
		return nil, err
	}
	c.m.SecretFetch.WithLabelValues("ok").Inc()
	return signer.Derive(mnemonic, v.HDPath, want)
}

// ClaimedFromEvents sums the withdraw_commission and withdraw_rewards event
// amounts of a confirmed tx.
func ClaimedFromEvents(res *sdk.TxResponse, denom string) map[string]math.Int {
	out := map[string]math.Int{
		SourceCommission:     math.ZeroInt(),
		SourceSelfDelegation: math.ZeroInt(),
	}
	for _, ev := range res.Events {
		var src string
		switch ev.Type {
		case "withdraw_commission":
			src = SourceCommission
		case "withdraw_rewards":
			src = SourceSelfDelegation
		default:
			continue
		}
		for _, a := range ev.Attributes {
			if a.Key != "amount" || a.Value == "" {
				continue
			}
			coins, err := sdk.ParseCoinsNormalized(a.Value)
			if err != nil {
				continue
			}
			out[src] = out[src].Add(coins.AmountOf(denom))
		}
	}
	return out
}

func backoff(failures int) time.Duration {
	d := retryBase
	for i := 1; i < failures && d < retryMax; i++ {
		d *= 2
	}
	return min(d, retryMax)
}
