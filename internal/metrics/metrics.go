// Package metrics defines the Prometheus metrics exported by sovr-harvest.
package metrics

import (
	"math/big"

	"cosmossdk.io/math"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const ns = "sovr_harvest"

// Label values. With this list, each series starts at zero before its first
// event. If a counter first shows at 1, Prometheus shows no increase() for it.
// Then the first failure after a restart is not visible.
var (
	ClaimResults = []string{"success", "failed", "below_threshold", "fee_too_high", "insufficient_balance", "no_grant", "dry_run"}
	ErrorStages  = []string{"query", "grant", "withdraw_address", "simulate", "secret", "sign", "broadcast", "confirm"}
	// RestakeResults has the claim results, and the results that only a
	// restake has.
	RestakeResults = append(append([]string{}, ClaimResults...), "withdraw_address_mismatch", "validator_not_bonded", "grant_limit")
)

type Metrics struct {
	Registry *prometheus.Registry

	BuildInfo *prometheus.GaugeVec

	ChainHeight        prometheus.Gauge
	PendingRewards     *prometheus.GaugeVec // validator, source
	ClaimableRewards   *prometheus.GaugeVec // validator
	MinClaim           *prometheus.GaugeVec // validator
	OutstandingRewards *prometheus.GaugeVec // validator
	ValidatorBonded    *prometheus.GaugeVec // validator
	ValidatorJailed    *prometheus.GaugeVec // validator
	ValidatorTokens    *prometheus.GaugeVec // validator
	AccountBalance     *prometheus.GaugeVec // validator, address, role
	NextClaim          *prometheus.GaugeVec // validator
	GrantExpiry        *prometheus.GaugeVec // validator, msg_type

	Claimed       *prometheus.CounterVec // validator, source
	FeesPaid      *prometheus.CounterVec // validator
	ClaimAttempts *prometheus.CounterVec // validator, result
	ClaimFailures *prometheus.GaugeVec   // validator
	LastClaim     *prometheus.GaugeVec   // validator
	LastClaimGas  *prometheus.GaugeVec   // validator

	Restakeable     *prometheus.GaugeVec   // validator
	MinRestake      *prometheus.GaugeVec   // validator
	RestakeInterval *prometheus.GaugeVec   // validator
	Restaked        *prometheus.CounterVec // validator
	RestakeFeesPaid *prometheus.CounterVec // validator
	RestakeAttempts *prometheus.CounterVec // validator, result
	RestakeFailures *prometheus.GaugeVec   // validator
	LastRestake     *prometheus.GaugeVec   // validator
	NextRestake     *prometheus.GaugeVec   // validator

	Polls       *prometheus.CounterVec // result
	LastPoll    prometheus.Gauge
	LastPollOK  prometheus.Gauge
	Errors      *prometheus.CounterVec // validator, stage
	SecretFetch *prometheus.CounterVec // result
	SecretTime  prometheus.Histogram
}

func New(version, chainID string) *Metrics {
	v := []string{"validator"}
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "build_info",
			Help: "Always 1. The labels show the build version and the configured chain."}, []string{"version", "chain_id"}),
		ChainHeight: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "chain_height",
			Help: "Latest block height that the last poll saw."}),
		PendingRewards: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "pending_usovr",
			Help: "Rewards that you can withdraw now, by source (commission, self_delegation)."}, []string{"validator", "source"}),
		ClaimableRewards: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "claimable_usovr",
			Help: "Pending rewards from the sources that this validator claims. A claim is due when this value gets to min_claim."}, v),
		MinClaim: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "min_claim_usovr",
			Help: "The min_claim value of the validator in the config."}, v),
		OutstandingRewards: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "validator_outstanding_usovr",
			Help: "All undistributed rewards for the validator. This includes the shares of other delegators."}, v),
		ValidatorBonded: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "validator_bonded",
			Help: "1 if the validator is in the bonded set."}, v),
		ValidatorJailed: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "validator_jailed",
			Help: "1 if the validator is jailed."}, v),
		ValidatorTokens: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "validator_tokens_usovr",
			Help: "Total tokens bonded to the validator."}, v),
		AccountBalance: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "account_balance_usovr",
			Help: "Spendable balance by role: signer (signs and pays the claim fees) or operator (shown when an authz grantee signs)."}, []string{"validator", "address", "role"}),
		NextClaim: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "next_claim_timestamp_seconds",
			Help: "Earliest time that the claimer can send the next claim."}, v),
		GrantExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "authz_grant_expiry_timestamp_seconds",
			Help: "Expiry of the authz grant from the operator to the grantee, by msg type. +Inf means no expiry. 0 means no grant."}, []string{"validator", "msg_type"}),
		Claimed: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "claimed_usovr_total",
			Help: "Rewards that this process claimed, from tx events, by source."}, []string{"validator", "source"}),
		FeesPaid: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "fees_paid_usovr_total",
			Help: "Fees for the claim txs that this process sent."}, v),
		ClaimAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "claim_attempts_total",
			Help: "Claim decisions by result: success, failed (a simulate, secret, sign, broadcast, or confirm error), below_threshold, fee_too_high, insufficient_balance, no_grant, dry_run."}, []string{"validator", "result"}),
		ClaimFailures: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "claim_consecutive_failures",
			Help: "Number of failed claim attempts in a row. A successful claim or a skipped claim sets it to 0."}, v),
		LastClaim: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_claim_timestamp_seconds",
			Help: "Time of the last confirmed claim tx that this process sent."}, v),
		LastClaimGas: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_claim_gas_used",
			Help: "Gas that the last confirmed claim tx used."}, v),
		Restakeable: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "restakeable_usovr",
			Help: "Amount that a restake can delegate now: the operator balance minus restake_reserve, and minus max_fee if the operator signs. 0 if the restake cannot run for a reason that is not the amount."}, v),
		MinRestake: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "min_restake_usovr",
			Help: "The min_restake value of the validator in the config."}, v),
		RestakeInterval: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "restake_interval_seconds",
			Help: "The restake_interval value in the config, for each validator with restake."}, v),
		Restaked: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "restaked_usovr_total",
			Help: "Tokens that this process delegated to the validator from the operator account."}, v),
		RestakeFeesPaid: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "restake_fees_paid_usovr_total",
			Help: "Fees for the restake txs that this process sent."}, v),
		RestakeAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "restake_attempts_total",
			Help: "Restake decisions by result: the claim results, and withdraw_address_mismatch, validator_not_bonded, grant_limit."}, []string{"validator", "result"}),
		RestakeFailures: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "restake_consecutive_failures",
			Help: "Number of failed restake attempts in a row. A successful restake or a skipped restake sets it to 0."}, v),
		LastRestake: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "last_restake_timestamp_seconds",
			Help: "Time of the last confirmed restake tx that this process sent."}, v),
		NextRestake: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "next_restake_timestamp_seconds",
			Help: "Earliest time that the claimer can send the next restake."}, v),
		Polls: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "polls_total",
			Help: "Poll cycles by result (ok, error)."}, []string{"result"}),
		LastPoll: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "last_poll_timestamp_seconds",
			Help: "Time of the last poll cycle."}),
		LastPollOK: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "last_successful_poll_timestamp_seconds",
			Help: "Time of the last poll cycle with no errors."}),
		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "errors_total",
			Help: "Errors by stage: query, grant, simulate, secret, sign, broadcast, confirm."}, []string{"validator", "stage"}),
		SecretFetch: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "secret_fetch_total",
			Help: "1Password secret fetches by result (ok, error)."}, []string{"result"}),
		SecretTime: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: "secret_fetch_duration_seconds",
			Help: "Time to get a secret from 1Password.", Buckets: []float64{.25, .5, 1, 2, 5, 10, 30}}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.BuildInfo, m.ChainHeight, m.PendingRewards, m.ClaimableRewards, m.MinClaim, m.OutstandingRewards, m.ValidatorBonded,
		m.ValidatorJailed, m.ValidatorTokens, m.AccountBalance, m.NextClaim, m.GrantExpiry, m.Claimed, m.FeesPaid,
		m.ClaimAttempts, m.ClaimFailures, m.LastClaim, m.LastClaimGas, m.Restakeable, m.MinRestake, m.RestakeInterval, m.Restaked,
		m.RestakeFeesPaid, m.RestakeAttempts, m.RestakeFailures, m.LastRestake, m.NextRestake, m.Polls, m.LastPoll, m.LastPollOK, m.Errors,
		m.SecretFetch, m.SecretTime,
	)
	m.BuildInfo.WithLabelValues(version, chainID).Set(1)
	for _, r := range []string{"ok", "error"} {
		m.Polls.WithLabelValues(r)
		m.SecretFetch.WithLabelValues(r)
	}
	return m
}

// InitValidator makes the counter series of val, with the value zero.
func (m *Metrics) InitValidator(val string, sources []string) {
	for _, r := range ClaimResults {
		m.ClaimAttempts.WithLabelValues(val, r)
	}
	for _, s := range ErrorStages {
		m.Errors.WithLabelValues(val, s)
	}
	for _, s := range sources {
		m.Claimed.WithLabelValues(val, s)
	}
	m.FeesPaid.WithLabelValues(val)
	m.ClaimFailures.WithLabelValues(val).Set(0)
}

// InitRestake makes the restake counter series of val, with the value zero.
func (m *Metrics) InitRestake(val string) {
	for _, r := range RestakeResults {
		m.RestakeAttempts.WithLabelValues(val, r)
	}
	m.Restaked.WithLabelValues(val)
	m.RestakeFeesPaid.WithLabelValues(val)
	m.RestakeFailures.WithLabelValues(val).Set(0)
}

// Float converts an integer amount to float64 for a gauge. The amounts are
// much less than 2^53. Thus, in practice, the conversion is exact.
func Float(i math.Int) float64 {
	f, _ := new(big.Float).SetInt(i.BigInt()).Float64()
	return f
}

func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
