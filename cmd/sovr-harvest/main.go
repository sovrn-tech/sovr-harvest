// Command sovr-harvest withdraws x/distribution rewards for SOVR validators
// at regular intervals. The rewards are the validator commission and the
// self-delegation rewards. The command also exports Prometheus metrics. It
// gets the signing mnemonic (of an authz grantee or of the operator) from
// 1Password or a local secrets file only immediately before it signs a
// claim. It does not write the mnemonic to disk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sovrn-tech/sovr-harvest/internal/chain"
	"github.com/sovrn-tech/sovr-harvest/internal/claimer"
	"github.com/sovrn-tech/sovr-harvest/internal/config"
	"github.com/sovrn-tech/sovr-harvest/internal/metrics"
	"github.com/sovrn-tech/sovr-harvest/internal/secret"
	"github.com/sovrn-tech/sovr-harvest/internal/signer"
)

var version = "dev"

const usage = `usage: sovr-harvest <command> [flags]

commands:
  run            poll on an interval, claim when due, serve metrics
  once           poll one time, without the schedule: claim, or restake if no claim is sent
  once -dry-run  query and simulate only, do not get key material
  check-secret   get each mnemonic, make sure it derives the signing address, exit
  version        print the version

flags:
  -config path   config file (default /etc/sovr-harvest/config.toml)
  -no-harden     do not use mlockall and PR_SET_DUMPABLE (for development)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := fs.String("config", "/etc/sovr-harvest/config.toml", "config file")
	dryRun := fs.Bool("dry-run", false, "query and simulate only")
	noHarden := fs.Bool("no-harden", false, "do not use memory hardening")
	_ = fs.Parse(os.Args[2:])

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if cmd == "version" {
		fmt.Println(version)
		return
	}
	if err := runCmd(cmd, *cfgPath, *dryRun, *noHarden, log); err != nil {
		log.Error(cmd+" failed", "err", err)
		os.Exit(1)
	}
}

func runCmd(cmd, cfgPath string, dryRun, noHarden bool, log *slog.Logger) error {
	switch cmd {
	case "run", "once", "check-secret":
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if !noHarden {
		if err := harden(); err != nil {
			return err
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	secrets := secret.Chain{OnePassword: &secret.OnePassword{TokenFile: cfg.OnePassword.TokenFile, Version: version}}
	if cfg.SecretsFile.Path != "" {
		secrets.File = &secret.File{Path: cfg.SecretsFile.Path}
	}
	if cmd == "check-secret" {
		return checkSecrets(ctx, cfg, secrets, log)
	}

	if cfg.PlaintextRemote() {
		log.Warn("grpc_insecure is set for a remote endpoint: anyone on the network path can feed the claimer "+
			"false chain state and make it pay up to max_fee per retry", "grpc", cfg.GRPCEndpoint)
	}
	client, err := chain.Dial(cfg.GRPCEndpoint, cfg.GRPCInsecure)
	if err != nil {
		return err
	}
	defer client.Close()
	m := metrics.New(version, cfg.ChainID)
	cl := claimer.New(cfg, client, secrets, m, log)

	if cmd == "once" {
		mode := claimer.ModeForce
		if dryRun {
			mode = claimer.ModeDryRun
		}
		return cl.Poll(ctx, mode)
	}
	if dryRun {
		return errors.New("-dry-run applies to once, not run")
	}
	return serve(ctx, cfg, cl, m, log)
}

func serve(ctx context.Context, cfg *config.Config, cl *claimer.Claimer, m *metrics.Metrics, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry}))
	// The loop waits poll_interval between polls, and a poll takes
	// MaxPollDuration or less. If no poll finishes in two times this sum, the
	// loop is stuck.
	var lastPoll atomic.Int64
	lastPoll.Store(time.Now().Unix())
	stale := 2 * (cfg.PollInterval.Duration + cl.MaxPollDuration())
	mux.Handle("/healthz", healthz(&lastPoll, stale, time.Now))
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()
	log.Info("started", "version", version, "listen", ln.Addr().String(), "grpc", cfg.GRPCEndpoint,
		"validators", len(cfg.Validators), "poll_interval", cfg.PollInterval.Duration)

	t := time.NewTicker(cfg.PollInterval.Duration)
	defer t.Stop()
	for {
		if err := cl.Poll(ctx, claimer.ModeScheduled); err != nil {
			log.Error("poll", "err", err)
		}
		lastPoll.Store(time.Now().Unix())
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(sctx)
		case <-t.C:
		}
	}
}

// healthz reports if the poll loop still runs. It returns 200 if a poll
// finished, or the process started, within stale. If not, it returns 503.
// It does not report if the polls are successful. The metrics and alerts
// show that.
func healthz(lastPoll *atomic.Int64, stale time.Duration, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		age := now().Sub(time.Unix(lastPoll.Load(), 0))
		if age > stale {
			http.Error(w, fmt.Sprintf("no poll finished in %s", age.Truncate(time.Second)), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
}

func checkSecrets(ctx context.Context, cfg *config.Config, secrets secret.Provider, log *slog.Logger) error {
	var errs []error
	for _, v := range cfg.Validators {
		acc := v.Grantee()
		if acc == nil {
			valoper, _ := sdk.ValAddressFromBech32(v.OperatorAddress) // config.Load validated it
			acc = sdk.AccAddress(valoper)
		}
		mnemonic, err := secrets.Fetch(ctx, v.MnemonicRef)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key, err := signer.Derive(mnemonic, v.HDPath, acc)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key.Wipe()
		log.Info("secret ok", "validator", v.OperatorAddress, "account", acc.String())
	}
	return errors.Join(errs...)
}
