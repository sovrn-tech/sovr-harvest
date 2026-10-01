package chain

import (
	"context"
	"net"
	"testing"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// fakeNode starts an in-memory gRPC server with the same codec as a node.
// register adds services to the server. fakeNode returns a Client that is
// connected to the server.
func fakeNode(t *testing.T, register func(*grpc.Server)) *Client {
	t.Helper()
	ln := bufconn.Listen(1 << 20)
	c, err := Dial("passthrough:///bufnet", true, grpc.WithContextDialer(
		func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	srv := grpc.NewServer(grpc.ForceServerCodec(protoNamedCodec{c.cdc.(*codec.ProtoCodec).GRPCCodec()}))
	register(srv)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return c
}

// authServer implements only AccountInfo. It does not implement Account.
// Thus, the test fails if the client decodes concrete account types again.
type authServer struct {
	authtypes.UnimplementedQueryServer
	info *authtypes.BaseAccount
}

func (s authServer) AccountInfo(context.Context, *authtypes.QueryAccountInfoRequest) (*authtypes.QueryAccountInfoResponse, error) {
	return &authtypes.QueryAccountInfoResponse{Info: s.info}, nil
}

// legacyAuthServer implements only Account, as a node before SDK v0.47 or
// a gateway without AccountInfo does.
type legacyAuthServer struct {
	authtypes.UnimplementedQueryServer
	acc sdk.AccountI
}

func (s legacyAuthServer) Account(context.Context, *authtypes.QueryAccountRequest) (*authtypes.QueryAccountResponse, error) {
	anyAcc, err := codectypes.NewAnyWithValue(s.acc)
	if err != nil {
		return nil, err
	}
	return &authtypes.QueryAccountResponse{Account: anyAcc}, nil
}

type bankServer struct {
	banktypes.UnimplementedQueryServer
	empty bool
}

func (s bankServer) SpendableBalanceByDenom(_ context.Context, r *banktypes.QuerySpendableBalanceByDenomRequest) (*banktypes.QuerySpendableBalanceByDenomResponse, error) {
	if s.empty {
		return &banktypes.QuerySpendableBalanceByDenomResponse{}, nil
	}
	c := sdk.NewInt64Coin(r.Denom, 7_000_000)
	return &banktypes.QuerySpendableBalanceByDenomResponse{Balance: &c}, nil
}

// TestAccountUsesAccountInfo reads an account over the network. It checks
// that the pubkey is correct after the decode.
func TestAccountUsesAccountInfo(t *testing.T) {
	for name, withPub := range map[string]bool{"pubkey": true, "never signed": false} {
		t.Run(name, func(t *testing.T) {
			pub := secp256k1.GenPrivKey().PubKey()
			addr := sdk.AccAddress(pub.Address())
			info := &authtypes.BaseAccount{Address: addr.String(), AccountNumber: 186, Sequence: 3}
			if withPub {
				anyPub, err := codectypes.NewAnyWithValue(pub)
				if err != nil {
					t.Fatal(err)
				}
				info.PubKey = anyPub
			}
			c := fakeNode(t, func(srv *grpc.Server) {
				authtypes.RegisterQueryServer(srv, &authServer{info: info})
				banktypes.RegisterQueryServer(srv, &bankServer{})
			})

			a, err := c.account(context.Background(), addr, "usovr")
			if err != nil {
				t.Fatal(err)
			}
			if a.AccountNumber != 186 || a.Sequence != 3 || !a.Balance.Equal(math.NewInt(7_000_000)) {
				t.Fatalf("account = %+v", a)
			}
			switch {
			case withPub && (a.PubKey == nil || !a.PubKey.Equals(pub)):
				t.Fatalf("pubkey = %v, want %v", a.PubKey, pub)
			case !withPub && a.PubKey != nil:
				t.Fatalf("pubkey = %v, want nil", a.PubKey)
			}
		})
	}
}

// TestAccountFallsBackToAccount reads a vesting account from a node without
// AccountInfo.
func TestAccountFallsBackToAccount(t *testing.T) {
	pub := secp256k1.GenPrivKey().PubKey()
	addr := sdk.AccAddress(pub.Address())
	base := authtypes.NewBaseAccount(addr, pub, 186, 3)
	acc, err := vestingtypes.NewContinuousVestingAccount(base, sdk.NewCoins(sdk.NewInt64Coin("usovr", 1)), 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	c := fakeNode(t, func(srv *grpc.Server) {
		authtypes.RegisterQueryServer(srv, &legacyAuthServer{acc: acc})
		banktypes.RegisterQueryServer(srv, &bankServer{})
	})
	a, err := c.account(context.Background(), addr, "usovr")
	if err != nil {
		t.Fatal(err)
	}
	if a.AccountNumber != 186 || a.Sequence != 3 || a.PubKey == nil || !a.PubKey.Equals(pub) {
		t.Fatalf("account = %+v", a)
	}
}

// emptyTxServer answers every call with an empty response, as a broken or
// hostile node can do.
type emptyTxServer struct {
	txtypes.UnimplementedServiceServer
}

func (emptyTxServer) Simulate(context.Context, *txtypes.SimulateRequest) (*txtypes.SimulateResponse, error) {
	return &txtypes.SimulateResponse{}, nil
}
func (emptyTxServer) BroadcastTx(context.Context, *txtypes.BroadcastTxRequest) (*txtypes.BroadcastTxResponse, error) {
	return &txtypes.BroadcastTxResponse{}, nil
}

// TestEmptyResponsesAreErrors checks that empty node responses return errors,
// and do not cause a panic on a nil field.
func TestEmptyResponsesAreErrors(t *testing.T) {
	addr := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	c := fakeNode(t, func(srv *grpc.Server) {
		authtypes.RegisterQueryServer(srv, &authServer{})
		banktypes.RegisterQueryServer(srv, &bankServer{empty: true})
		txtypes.RegisterServiceServer(srv, &emptyTxServer{})
	})
	ctx := context.Background()
	if _, err := c.account(ctx, addr, "usovr"); err == nil {
		t.Error("account: expected error for missing info")
	}
	info := &authtypes.BaseAccount{Address: addr.String()}
	c2 := fakeNode(t, func(srv *grpc.Server) {
		authtypes.RegisterQueryServer(srv, &authServer{info: info})
		banktypes.RegisterQueryServer(srv, &bankServer{empty: true})
	})
	if _, err := c2.account(ctx, addr, "usovr"); err == nil {
		t.Error("account: expected error for missing balance")
	}
	tx := Tx{GasLimit: 1, Fee: sdk.NewCoins(sdk.NewInt64Coin("usovr", 1))}
	if _, err := c.Simulate(ctx, tx, &secp256k1.PubKey{}, 0); err == nil {
		t.Error("simulate: expected error for missing gas info")
	}
	if _, err := c.Broadcast(ctx, []byte("tx")); err == nil {
		t.Error("broadcast: expected error for missing tx response")
	}
}

type authzServer struct {
	authz.UnimplementedQueryServer
	grants []authz.Authorization
}

func (s authzServer) Grants(context.Context, *authz.QueryGrantsRequest) (*authz.QueryGrantsResponse, error) {
	res := &authz.QueryGrantsResponse{}
	for _, a := range s.grants {
		anyAuth, err := codectypes.NewAnyWithValue(a)
		if err != nil {
			return nil, err
		}
		res.Grants = append(res.Grants, &authz.Grant{Authorization: anyAuth})
	}
	return res, nil
}

// TestGrantsDecodesStakeAuthorization reads a delegate grant. Before the
// client registered the staking types, the decode of this grant failed.
// Then each snapshot of a grantee with a delegate grant failed.
func TestGrantsDecodesStakeAuthorization(t *testing.T) {
	granter := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	grantee := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	stake, err := stakingtypes.NewStakeAuthorization([]sdk.ValAddress{sdk.ValAddress(granter)}, nil,
		stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE, nil)
	if err != nil {
		t.Fatal(err)
	}
	withdraw := sdk.MsgTypeURL(&distrtypes.MsgWithdrawDelegatorReward{})
	c := fakeNode(t, func(srv *grpc.Server) {
		authz.RegisterQueryServer(srv, &authzServer{grants: []authz.Authorization{
			authz.NewGenericAuthorization(withdraw), stake,
		}})
	})
	got, err := c.grants(context.Background(), granter, grantee)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[withdraw].Authorization.(*authz.GenericAuthorization); !ok {
		t.Fatalf("withdraw grant = %T", got[withdraw].Authorization)
	}
	sa, ok := got[sdk.MsgTypeURL(&stakingtypes.MsgDelegate{})].Authorization.(*stakingtypes.StakeAuthorization)
	if !ok {
		t.Fatalf("delegate grant = %T", got[sdk.MsgTypeURL(&stakingtypes.MsgDelegate{})].Authorization)
	}
	if l := sa.GetAllowList().GetAddress(); len(l) != 1 || l[0] != sdk.ValAddress(granter).String() {
		t.Fatalf("allow list = %v", l)
	}
}

// TestGrantsRejectsUnknownStakeType checks that a StakeAuthorization with
// an authorization type that is not known gives an error. Before this
// check, MsgTypeURL caused a panic.
func TestGrantsRejectsUnknownStakeType(t *testing.T) {
	granter := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	grantee := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	for name, typ := range map[string]stakingtypes.AuthorizationType{
		"unspecified": stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_UNSPECIFIED,
		"unknown":     stakingtypes.AuthorizationType(99),
	} {
		t.Run(name, func(t *testing.T) {
			stake := &stakingtypes.StakeAuthorization{AuthorizationType: typ}
			c := fakeNode(t, func(srv *grpc.Server) {
				authz.RegisterQueryServer(srv, &authzServer{grants: []authz.Authorization{stake}})
			})
			if got, err := c.grants(context.Background(), granter, grantee); err == nil {
				t.Fatalf("got %v, want error", got)
			}
		})
	}
}

type distrServer struct {
	distrtypes.UnimplementedQueryServer
	withdraw string
}

func (s distrServer) DelegatorWithdrawAddress(context.Context, *distrtypes.QueryDelegatorWithdrawAddressRequest) (*distrtypes.QueryDelegatorWithdrawAddressResponse, error) {
	return &distrtypes.QueryDelegatorWithdrawAddressResponse{WithdrawAddress: s.withdraw}, nil
}

// TestWithdrawAddress checks that an empty or incorrect withdraw address
// from the node is an error.
func TestWithdrawAddress(t *testing.T) {
	addr := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	for name, tc := range map[string]struct {
		reply string
		ok    bool
	}{
		"valid":   {addr.String(), true},
		"empty":   {"", false},
		"valoper": {sdk.ValAddress(addr).String(), false},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeNode(t, func(srv *grpc.Server) {
				distrtypes.RegisterQueryServer(srv, &distrServer{withdraw: tc.reply})
			})
			got, err := c.withdrawAddress(context.Background(), addr)
			switch {
			case tc.ok && (err != nil || !got.Equals(addr)):
				t.Fatalf("got %s, %v; want %s", got, err, addr)
			case !tc.ok && err == nil:
				t.Fatalf("got %s, want error", got)
			}
		})
	}
}
