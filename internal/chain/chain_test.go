package chain

import (
	"context"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/cosmos/cosmos-sdk/x/authz"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
)

// TestSignVerifies signs a claim tx offline. It checks the signature in the
// same way as the chain ante handler.
func TestSignVerifies(t *testing.T) {
	c, err := Dial("127.0.0.1:1", true) // the test does not connect to it
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	priv := secp256k1.GenPrivKey()
	acc := sdk.AccAddress(priv.PubKey().Address())
	val := sdk.ValAddress(acc).String()
	tx := Tx{
		Msgs: []sdk.Msg{
			&distrtypes.MsgWithdrawValidatorCommission{ValidatorAddress: val},
			&distrtypes.MsgWithdrawDelegatorReward{DelegatorAddress: acc.String(), ValidatorAddress: val},
		},
		GasLimit: 200000,
		Fee:      sdk.NewCoins(sdk.NewInt64Coin("usovr", 400)),
	}
	const chainID, accNum, seq = "sovr-1", uint64(186), uint64(3)
	bz, err := c.Sign(context.Background(), tx, priv, chainID, accNum, seq)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := c.txCfg.TxDecoder()(bz)
	if err != nil {
		t.Fatal(err)
	}
	sigTx := decoded.(authsigning.Tx)
	sigs, err := sigTx.GetSignaturesV2()
	if err != nil || len(sigs) != 1 {
		t.Fatalf("sigs=%v err=%v", sigs, err)
	}
	signers, err := sigTx.GetSigners()
	if err != nil || len(signers) != 1 || !sdk.AccAddress(signers[0]).Equals(acc) {
		t.Fatalf("signers=%v err=%v", signers, err)
	}

	signerData := authsigning.SignerData{
		ChainID: chainID, AccountNumber: accNum, Sequence: seq,
		PubKey: priv.PubKey(), Address: acc.String(),
	}
	if !verify(t, c, signerData, sigTx, sigs[0].Data) {
		t.Fatal("signature does not verify")
	}
	// The same signature must not verify for another chain or account.
	for _, mutate := range []func(*authsigning.SignerData){
		func(d *authsigning.SignerData) { d.ChainID = "test-sovr-1" },
		func(d *authsigning.SignerData) { d.AccountNumber++ },
	} {
		d := signerData
		mutate(&d)
		if verify(t, c, d, sigTx, sigs[0].Data) {
			t.Fatalf("signature verified under %+v", d)
		}
	}
	// DIRECT mode signs the sequence in the tx signer info. The ante handler
	// compares it with the account. Thus, it must be the sequence that we gave.
	if sigs[0].Sequence != seq {
		t.Fatalf("signed sequence %d, want %d", sigs[0].Sequence, seq)
	}
}

// TestSignExec encodes and decodes an authz MsgExec claim. It checks that
// the claim does not change and that the grantee is its only signer.
func TestSignExec(t *testing.T) {
	c, err := Dial("127.0.0.1:1", true) // the test does not connect to it
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	priv := secp256k1.GenPrivKey()
	grantee := sdk.AccAddress(priv.PubKey().Address())
	op := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	val := sdk.ValAddress(op).String()
	exec := authz.NewMsgExec(grantee, []sdk.Msg{
		&distrtypes.MsgWithdrawValidatorCommission{ValidatorAddress: val},
		&distrtypes.MsgWithdrawDelegatorReward{DelegatorAddress: op.String(), ValidatorAddress: val},
	})
	tx := Tx{Msgs: []sdk.Msg{&exec}, GasLimit: 200000, Fee: sdk.NewCoins(sdk.NewInt64Coin("usovr", 400))}
	bz, err := c.Sign(context.Background(), tx, priv, "sovr-1", 900, 0)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := c.txCfg.TxDecoder()(bz)
	if err != nil {
		t.Fatal(err)
	}
	sigTx := decoded.(authsigning.Tx)
	signers, err := sigTx.GetSigners()
	if err != nil || len(signers) != 1 || !sdk.AccAddress(signers[0]).Equals(grantee) {
		t.Fatalf("signers=%v err=%v, want only the grantee", signers, err)
	}
	msgs := sigTx.GetMsgs()
	inner, err := msgs[0].(*authz.MsgExec).GetMessages()
	if err != nil || len(inner) != 2 {
		t.Fatalf("inner=%v err=%v", inner, err)
	}
}

// verify calculates the SIGN_MODE_DIRECT sign bytes again from the decoded
// tx, as the ante handler does. Then it checks the signature with them.
func verify(t *testing.T, c *Client, d authsigning.SignerData, tx authsigning.Tx, data signing.SignatureData) bool {
	t.Helper()
	single, ok := data.(*signing.SingleSignatureData)
	if !ok || single.SignMode != signing.SignMode_SIGN_MODE_DIRECT {
		t.Fatalf("unexpected signature data %T", data)
	}
	bz, err := authsigning.GetSignBytesAdapter(context.Background(), c.txCfg.SignModeHandler(), single.SignMode, d, tx)
	if err != nil {
		t.Fatal(err)
	}
	return d.PubKey.VerifySignature(bz, single.Signature)
}
