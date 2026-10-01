// Package secret gets key material only when the claimer asks for it. This
// package does not cache secrets. Each Fetch reads the service account token
// (or secrets file) from disk and resolves one reference. It gives the value
// to the caller. The caller must write zeros over it.
package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/1password/onepassword-sdk-go"
	"github.com/BurntSushi/toml"
)

// Provider resolves a secret reference to its value. The caller owns the
// returned slice. After the caller uses it, the caller must call Wipe.
type Provider interface {
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

// Wipe writes zeros over b.
func Wipe(b []byte) { clear(b) }

const credentialName = "op-service-account-token"

// secretsFileCredentialName is the LoadCredential name that nix/module.nix
// gives to the secrets file.
const secretsFileCredentialName = "sovr-harvest-secrets"

// OnePassword resolves op:// references with a 1Password service account.
type OnePassword struct {
	// TokenFile, if set, is the file that holds the service account token.
	TokenFile string
	Version   string
}

func (o OnePassword) Fetch(ctx context.Context, ref string) ([]byte, error) {
	token, err := o.token()
	if err != nil {
		return nil, err
	}
	// The SDK takes the token and returns the secret as Go strings. We cannot
	// write zeros over strings. When this function returns, the program has no
	// reference to them.
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(string(token)),
		onepassword.WithIntegrationInfo("sovr-harvest", o.Version),
	)
	Wipe(token)
	if err != nil {
		return nil, fmt.Errorf("1password client: %w", err)
	}
	v, err := client.Secrets().Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("1password resolve %s: %w", ref, err)
	}
	if v == "" {
		return nil, fmt.Errorf("1password resolve %s: empty value", ref)
	}
	return []byte(v), nil
}

func (o OnePassword) token() ([]byte, error) {
	path := o.TokenFile
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			path = filepath.Join(dir, credentialName)
		}
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read 1password token: %w", err)
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return nil, fmt.Errorf("1password token file %s is empty", path)
		}
		return b, nil
	}
	if t := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"); t != "" {
		return []byte(t), nil
	}
	return nil, errors.New("no 1password service account token: set onepassword.token_file, " +
		"provide the " + credentialName + " systemd credential, or set OP_SERVICE_ACCOUNT_TOKEN")
}

// File resolves file:// references against a local TOML file. The file has
// one key = value pair per mnemonic. Use it on hosts that cannot run
// 1Password. Each Fetch reads the file again. The package does not cache it.
type File struct {
	// Path is the secrets file. It must be readable only by its owner.
	Path string
}

func (f File) Fetch(_ context.Context, ref string) ([]byte, error) {
	key, ok := strings.CutPrefix(ref, "file://")
	if !ok {
		return nil, fmt.Errorf("not a file:// reference: %s", ref)
	}
	fh, path, err := f.open()
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	// Examine the open handle, not the path. If the path changes after the
	// open, this check and the read below still use the same file.
	fi, err := fh.Stat()
	if err != nil {
		return nil, fmt.Errorf("secrets file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secrets file %s must not be readable by group or other (mode %o)",
			path, fi.Mode().Perm())
	}
	// The decoder returns Go strings. We cannot write zeros over strings.
	// When this function returns, the program has no reference to them.
	var m map[string]string
	if _, err := toml.NewDecoder(fh).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse secrets file %s: %w", path, err)
	}
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("no key %q in secrets file %s", key, path)
	}
	if v == "" {
		return nil, fmt.Errorf("key %q in secrets file %s is empty", key, path)
	}
	return []byte(v), nil
}

// open opens the secrets file and returns the path that it opened. If f.Path
// does not exist and systemd set CREDENTIALS_DIRECTORY, open tries the
// secretsFileCredentialName credential in that directory. This is necessary
// if the configured path has an incorrect credential directory. If the second
// open also fails, open returns the first error.
func (f File) open() (*os.File, string, error) {
	fh, err := os.Open(f.Path)
	if err == nil {
		return fh, f.Path, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			alt := filepath.Join(dir, secretsFileCredentialName)
			if afh, aerr := os.Open(alt); aerr == nil {
				return afh, alt, nil
			}
		}
	}
	return nil, "", fmt.Errorf("secrets file: %w", err)
}

// Chain sends a Fetch to OnePassword or File, based on the scheme of the
// reference. A nil field means the claimer did not set up that scheme.
type Chain struct {
	OnePassword *OnePassword
	File        *File
}

func (c Chain) Fetch(ctx context.Context, ref string) ([]byte, error) {
	switch {
	case strings.HasPrefix(ref, "op://"):
		if c.OnePassword == nil {
			return nil, fmt.Errorf("op:// reference but 1password is not configured: %s", ref)
		}
		return c.OnePassword.Fetch(ctx, ref)
	case strings.HasPrefix(ref, "file://"):
		if c.File == nil {
			return nil, fmt.Errorf("file:// reference but secrets_file is not configured: %s", ref)
		}
		return c.File.Fetch(ctx, ref)
	default:
		return nil, fmt.Errorf("unsupported secret reference: %s", ref)
	}
}

// Static returns fixed values. Use it only in tests.
type Static map[string]string

func (s Static) Fetch(_ context.Context, ref string) ([]byte, error) {
	v, ok := s[ref]
	if !ok {
		return nil, fmt.Errorf("no secret for %s", ref)
	}
	return []byte(v), nil
}
