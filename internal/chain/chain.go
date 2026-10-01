// Package chain connects to a SOVR node over gRPC. It sends read-only
// queries, simulates txs without a key, and signs and broadcasts claim txs.
package chain

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"cosmossdk.io/math"
	txsigning "cosmossdk.io/x/tx/signing"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	clienttx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"

	"github.com/sovrn-tech/sovr-harvest/internal/sovr"
)

type Client struct {
	conn    *grpc.ClientConn
	cdc     codec.Codec
	txCfg   client.TxConfig
	auth    authtypes.QueryClient
	authz   authz.QueryClient
	bank    banktypes.QueryClient
	distr   distrtypes.QueryClient
	staking stakingtypes.QueryClient
	cmt     cmtservice.ServiceClient
	tx      txtypes.ServiceClient
}

// Dial connects to endpoint. Dial adds the extra opts after the defaults.
// The tests use them to connect to an in-memory server.
func Dial(endpoint string, plaintext bool, opts ...grpc.DialOption) (*Client, error) {
	sovr.Init()
	signingOpts := txsigning.Options{
		AddressCodec:          addresscodec.NewBech32Codec(sovr.AccountPrefix),
		ValidatorAddressCodec: addresscodec.NewBech32Codec(sovr.ValidatorPrefix),
	}
	reg, err := codectypes.NewInterfaceRegistryWithOptions(codectypes.InterfaceRegistryOptions{
		ProtoFiles:     proto.HybridResolver,
		SigningOptions: signingOpts,
	})
	if err != nil {
		return nil, err
	}
	std.RegisterInterfaces(reg)
	authtypes.RegisterInterfaces(reg)
	vestingtypes.RegisterInterfaces(reg) // for the Account fallback
	distrtypes.RegisterInterfaces(reg)
	authz.RegisterInterfaces(reg)
	stakingtypes.RegisterInterfaces(reg) // for StakeAuthorization and MsgDelegate
	cdc := codec.NewProtoCodec(reg)
	txCfg, err := authtx.NewTxConfigWithOptions(cdc, authtx.ConfigOptions{
		EnabledSignModes: []signing.SignMode{signing.SignMode_SIGN_MODE_DIRECT},
		SigningOptions:   &signingOpts,
	})
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if plaintext {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(endpoint, append([]grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(protoNamedCodec{cdc.GRPCCodec()})),
	}, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", endpoint, err)
	}
	return &Client{
		conn:    conn,
		cdc:     cdc,
		txCfg:   txCfg,
		auth:    authtypes.NewQueryClient(conn),
		authz:   authz.NewQueryClient(conn),
		bank:    banktypes.NewQueryClient(conn),
		distr:   distrtypes.NewQueryClient(conn),
		staking: stakingtypes.NewQueryClient(conn),
		cmt:     cmtservice.NewServiceClient(conn),
		tx:      txtypes.NewServiceClient(conn),
	}, nil
}

// protoNamedCodec is the SDK gRPC codec with the standard name "proto". The
// gogoproto types need the SDK codec. The SDK codec has the name
// "cosmos-sdk-grpc-codec", and this name becomes the request content-type.
// Some proxies reset streams with that content-type. An example is the
// Cloudflare proxy in front of grpc.sovrchain.net.
type protoNamedCodec struct{ encoding.Codec }

func (protoNamedCodec) Name() string { return "proto" }

func (c *Client) Close() error { return c.conn.Close() }

// Account is an on-chain account that can sign and pay for a claim tx.
type Account struct {
	Address       sdk.AccAddress
	AccountNumber uint64
	Sequence      uint64
	PubKey        cryptotypes.PubKey // nil if the account did not sign a tx before
	Balance       math.Int           // spendable balance in the fee denom
}

// Snapshot is all the data that the claimer needs about one validator. The
// claimer gets this data without key material.
type Snapshot struct {
	ChainID   string
	Height    int64
	BlockTime time.Time

	Moniker     string
	Bonded      bool
	Jailed      bool
	Tokens      math.Int
	Outstanding math.Int // all undistributed rewards for the validator

	Operator Account
	// WithdrawAddress is the account that gets the rewards of the operator.
	// It is nil if the caller did not ask for it, or if the query failed.
	WithdrawAddress sdk.AccAddress
	// WithdrawAddressErr is the error of the withdraw address query. Only a
	// restake uses the withdraw address. Thus, this error does not stop the
	// snapshot, and a claim can continue.
	WithdrawAddressErr error
	// Grantee is the authz grantee that signs the claims, if the config has one.
	Grantee *Account
	// Grants maps each msg type URL that the operator granted to Grantee to
	// the grant.
	Grants map[string]Grant

	Commission  math.Int // commission that you can withdraw, truncated to whole base units
	SelfRewards math.Int // rewards on the self-delegation, truncated
}

// Grant is an authz grant from the operator to the grantee.
type Grant struct {
	Expiry        *time.Time // nil means no expiry
	Authorization authz.Authorization
}

// Signer is the account that signs and pays for the claim tx: the grantee
// if there is one. If not, the operator.
func (s *Snapshot) Signer() *Account {
	if s.Grantee != nil {
		return s.Grantee
	}
	return &s.Operator
}

// Snapshot queries the chain for valoper. If grantee is not nil, it also
// gets that account and the authz grants that the operator gave to it. If
// withdraw is true, it also gets the withdraw address of the operator. If
// not, WithdrawAddress is nil. If that query fails, Snapshot puts the error
// in WithdrawAddressErr and does not return it.
func (c *Client) Snapshot(ctx context.Context, valoper sdk.ValAddress, denom string, grantee sdk.AccAddress, withdraw bool) (*Snapshot, error) {
	acc := sdk.AccAddress(valoper)
	s := &Snapshot{}

	blk, err := c.cmt.GetLatestBlock(ctx, &cmtservice.GetLatestBlockRequest{})
	if err != nil {
		return nil, fmt.Errorf("latest block: %w", err)
	}
	if blk.SdkBlock == nil {
		return nil, errors.New("latest block: node returned no sdk_block")
	}
	s.ChainID = blk.SdkBlock.Header.ChainID
	s.Height = blk.SdkBlock.Header.Height
	s.BlockTime = blk.SdkBlock.Header.Time

	val, err := c.staking.Validator(ctx, &stakingtypes.QueryValidatorRequest{ValidatorAddr: valoper.String()})
	if err != nil {
		return nil, fmt.Errorf("validator: %w", err)
	}
	s.Moniker = val.Validator.Description.Moniker
	s.Bonded = val.Validator.Status == stakingtypes.Bonded
	s.Jailed = val.Validator.Jailed
	s.Tokens = val.Validator.Tokens

	op, err := c.account(ctx, acc, denom)
	if err != nil {
		return nil, fmt.Errorf("operator %w", err)
	}
	s.Operator = *op
	if withdraw {
		s.WithdrawAddress, s.WithdrawAddressErr = c.withdrawAddress(ctx, acc)
	}
	if grantee != nil {
		if s.Grantee, err = c.account(ctx, grantee, denom); err != nil {
			return nil, fmt.Errorf("grantee %w", err)
		}
		if s.Grants, err = c.grants(ctx, acc, grantee); err != nil {
			return nil, err
		}
	}

	out, err := c.distr.ValidatorOutstandingRewards(ctx, &distrtypes.QueryValidatorOutstandingRewardsRequest{ValidatorAddress: valoper.String()})
	if err != nil {
		return nil, fmt.Errorf("outstanding rewards: %w", err)
	}
	s.Outstanding = out.Rewards.Rewards.AmountOf(denom).TruncateInt()

	com, err := c.distr.ValidatorCommission(ctx, &distrtypes.QueryValidatorCommissionRequest{ValidatorAddress: valoper.String()})
	if err != nil {
		return nil, fmt.Errorf("commission: %w", err)
	}
	s.Commission = com.Commission.Commission.AmountOf(denom).TruncateInt()

	s.SelfRewards = math.ZeroInt()
	rew, err := c.distr.DelegationTotalRewards(ctx, &distrtypes.QueryDelegationTotalRewardsRequest{DelegatorAddress: acc.String()})
	if err != nil {
		return nil, fmt.Errorf("delegation rewards: %w", err)
	}
	for _, r := range rew.Rewards {
		if r.ValidatorAddress == valoper.String() {
			s.SelfRewards = r.Reward.AmountOf(denom).TruncateInt()
		}
	}
	return s, nil
}

func (c *Client) account(ctx context.Context, addr sdk.AccAddress, denom string) (*Account, error) {
	// Use AccountInfo, not Account. AccountInfo returns the number, sequence,
	// and pubkey as a BaseAccount for all concrete account types. Account
	// returns the concrete type in an Any. The decode of that Any fails for
	// each type that is not in our registry, for example the custom SOVR
	// account types.
	var info sdk.AccountI
	res, err := c.auth.AccountInfo(ctx, &authtypes.QueryAccountInfoRequest{Address: addr.String()})
	switch {
	case status.Code(err) == codes.Unimplemented:
		// AccountInfo is in SDK v0.47 and later, and some gateways do not
		// provide it.
		if info, err = c.accountFallback(ctx, addr); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("account %s: %w", addr, err)
	case res.Info == nil:
		return nil, fmt.Errorf("account %s: node returned no account info", addr)
	default:
		if err := res.Info.UnpackInterfaces(c.cdc); err != nil {
			return nil, fmt.Errorf("decode account %s pubkey: %w", addr, err)
		}
		info = res.Info
	}
	a := &Account{
		Address:       addr,
		AccountNumber: info.GetAccountNumber(),
		Sequence:      info.GetSequence(),
		PubKey:        info.GetPubKey(),
	}
	// Use the spendable balance, not the total. Locked vesting coins cannot
	// pay a fee.
	bal, err := c.bank.SpendableBalanceByDenom(ctx, &banktypes.QuerySpendableBalanceByDenomRequest{Address: addr.String(), Denom: denom})
	if err != nil {
		return nil, fmt.Errorf("balance %s: %w", addr, err)
	}
	if bal.Balance == nil || bal.Balance.Amount.IsNil() {
		return nil, fmt.Errorf("balance %s: node returned no balance", addr)
	}
	a.Balance = bal.Balance.Amount
	return a, nil
}

// accountFallback reads addr with Query/Account, for nodes that do not have
// AccountInfo. It decodes only the account types in our registry: base,
// module, and vesting accounts.
func (c *Client) accountFallback(ctx context.Context, addr sdk.AccAddress) (sdk.AccountI, error) {
	res, err := c.auth.Account(ctx, &authtypes.QueryAccountRequest{Address: addr.String()})
	if err != nil {
		return nil, fmt.Errorf("account %s (AccountInfo unimplemented): %w", addr, err)
	}
	if res.Account == nil {
		return nil, fmt.Errorf("account %s: node returned no account", addr)
	}
	var acc sdk.AccountI
	if err := c.cdc.UnpackAny(res.Account, &acc); err != nil {
		return nil, fmt.Errorf("decode account %s (AccountInfo unimplemented): %w", addr, err)
	}
	return acc, nil
}

func (c *Client) withdrawAddress(ctx context.Context, delegator sdk.AccAddress) (sdk.AccAddress, error) {
	res, err := c.distr.DelegatorWithdrawAddress(ctx, &distrtypes.QueryDelegatorWithdrawAddressRequest{DelegatorAddress: delegator.String()})
	if err != nil {
		return nil, fmt.Errorf("withdraw address: %w", err)
	}
	addr, err := sdk.AccAddressFromBech32(res.WithdrawAddress)
	if err != nil {
		return nil, fmt.Errorf("withdraw address: node returned %q: %w", res.WithdrawAddress, err)
	}
	return addr, nil
}

func (c *Client) grants(ctx context.Context, granter, grantee sdk.AccAddress) (map[string]Grant, error) {
	out := map[string]Grant{}
	req := &authz.QueryGrantsRequest{Granter: granter.String(), Grantee: grantee.String()}
	for {
		res, err := c.authz.Grants(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("authz grants: %w", err)
		}
		for _, g := range res.Grants {
			var a authz.Authorization
			if err := c.cdc.UnpackAny(g.Authorization, &a); err != nil {
				return nil, fmt.Errorf("decode authz grant: %w", err)
			}
			if a == nil {
				return nil, errors.New("decode authz grant: node returned a grant with no authorization")
			}
			if err := checkAuthzType(a); err != nil {
				return nil, fmt.Errorf("decode authz grant: %w", err)
			}
			out[a.MsgTypeURL()] = Grant{Expiry: g.Expiration, Authorization: a}
		}
		if res.Pagination == nil || len(res.Pagination.NextKey) == 0 {
			return out, nil
		}
		req.Pagination = &query.PageRequest{Key: res.Pagination.NextKey}
	}
}

// checkAuthzType makes sure that a.MsgTypeURL does not panic. For an
// authorization type that is not known, StakeAuthorization.MsgTypeURL
// panics.
func checkAuthzType(a authz.Authorization) error {
	sa, ok := a.(*stakingtypes.StakeAuthorization)
	if !ok {
		return nil
	}
	switch sa.AuthorizationType {
	case stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE,
		stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE,
		stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE,
		stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_CANCEL_UNBONDING_DELEGATION:
		return nil
	default:
		return fmt.Errorf("node returned a StakeAuthorization with authorization type %d", sa.AuthorizationType)
	}
}

// Tx is an unsigned claim tx.
type Tx struct {
	Msgs     []sdk.Msg
	GasLimit uint64
	Fee      sdk.Coins
	Memo     string
}

func (c *Client) build(tx Tx, pub cryptotypes.PubKey, seq uint64) (client.TxBuilder, error) {
	b := c.txCfg.NewTxBuilder()
	if err := b.SetMsgs(tx.Msgs...); err != nil {
		return nil, err
	}
	b.SetGasLimit(tx.GasLimit)
	b.SetFeeAmount(tx.Fee)
	b.SetMemo(tx.Memo)
	// The simulation expects an empty signature with the pubkey.
	// SIGN_MODE_DIRECT needs the signer info before it makes the sign bytes.
	err := b.SetSignatures(signing.SignatureV2{
		PubKey:   pub,
		Data:     &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT},
		Sequence: seq,
	})
	return b, err
}

// Simulate returns the gas used by tx. It needs only the public key.
func (c *Client) Simulate(ctx context.Context, tx Tx, pub cryptotypes.PubKey, seq uint64) (uint64, error) {
	b, err := c.build(tx, pub, seq)
	if err != nil {
		return 0, err
	}
	bz, err := c.txCfg.TxEncoder()(b.GetTx())
	if err != nil {
		return 0, err
	}
	res, err := c.tx.Simulate(ctx, &txtypes.SimulateRequest{TxBytes: bz})
	if err != nil {
		return 0, fmt.Errorf("simulate: %w", err)
	}
	if res.GasInfo == nil {
		return 0, errors.New("simulate: node returned no gas info")
	}
	return res.GasInfo.GasUsed, nil
}

// Sign signs tx with SIGN_MODE_DIRECT and returns the encoded bytes.
func (c *Client) Sign(ctx context.Context, tx Tx, priv cryptotypes.PrivKey, chainID string, accNum, seq uint64) ([]byte, error) {
	pub := priv.PubKey()
	b, err := c.build(tx, pub, seq)
	if err != nil {
		return nil, err
	}
	signerData := authsigning.SignerData{
		ChainID:       chainID,
		AccountNumber: accNum,
		Sequence:      seq,
		PubKey:        pub,
		Address:       sdk.AccAddress(pub.Address()).String(),
	}
	sig, err := clienttx.SignWithPrivKey(ctx, signing.SignMode_SIGN_MODE_DIRECT, signerData, b, priv, c.txCfg, seq)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := b.SetSignatures(sig); err != nil {
		return nil, err
	}
	return c.txCfg.TxEncoder()(b.GetTx())
}

// ErrTxFailed wraps a tx that CheckTx rejected, or that failed in a block.
var ErrTxFailed = errors.New("tx failed")

// Broadcast sends a signed tx in sync mode. After the tx passes CheckTx,
// Broadcast returns its hash.
func (c *Client) Broadcast(ctx context.Context, txBytes []byte) (string, error) {
	res, err := c.tx.BroadcastTx(ctx, &txtypes.BroadcastTxRequest{TxBytes: txBytes, Mode: txtypes.BroadcastMode_BROADCAST_MODE_SYNC})
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	r := res.TxResponse
	if r == nil {
		return "", errors.New("broadcast: node returned no tx response")
	}
	if r.Code != 0 {
		return r.TxHash, fmt.Errorf("%w: checktx code %d (%s): %s", ErrTxFailed, r.Code, r.Codespace, r.RawLog)
	}
	return r.TxHash, nil
}

// WaitTx polls until hash is in a block or ctx ends.
func (c *Client) WaitTx(ctx context.Context, hash string) (*sdk.TxResponse, error) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		res, err := c.tx.GetTx(ctx, &txtypes.GetTxRequest{Hash: hash})
		if err == nil && res.TxResponse != nil {
			r := res.TxResponse
			if r.Code != 0 {
				return r, fmt.Errorf("%w: code %d (%s): %s", ErrTxFailed, r.Code, r.Codespace, r.RawLog)
			}
			return r, nil
		}
		// Nodes report a tx that is not indexed yet as NotFound. Some nodes
		// report it as Internal. Thus, for all errors and for an empty
		// response, poll again.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("tx %s not confirmed: %w", hash, ctx.Err())
		case <-t.C:
		}
	}
}
