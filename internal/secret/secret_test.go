package secret

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecrets(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.toml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileFetch(t *testing.T) {
	p := writeSecrets(t, `validator1 = "word1 word2"`+"\n", 0o600)
	f := File{Path: p}
	v, err := f.Fetch(context.Background(), "file://validator1")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "word1 word2" {
		t.Fatalf("got %q", v)
	}
}

func TestFileFetchRejectsLoosePermissions(t *testing.T) {
	p := writeSecrets(t, `validator1 = "word1 word2"`+"\n", 0o644)
	f := File{Path: p}
	if _, err := f.Fetch(context.Background(), "file://validator1"); err == nil {
		t.Fatal("expected error for world-readable secrets file")
	}
}

func TestFileFetchMissingKey(t *testing.T) {
	p := writeSecrets(t, `validator1 = "word1 word2"`+"\n", 0o600)
	f := File{Path: p}
	if _, err := f.Fetch(context.Background(), "file://nope"); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFileFetchNotFileRef(t *testing.T) {
	f := File{Path: "/nonexistent"}
	if _, err := f.Fetch(context.Background(), "op://vault/item/field"); err == nil {
		t.Fatal("expected error for non-file:// reference")
	}
}

func TestFileFetchCredentialsDirectoryFallback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, secretsFileCredentialName)
	if err := os.WriteFile(p, []byte(`validator1 = "word1 word2"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	f := File{Path: "/nonexistent/path"}
	v, err := f.Fetch(context.Background(), "file://validator1")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "word1 word2" {
		t.Fatalf("got %q", v)
	}
}

func TestFileFetchMissingFileNoCredentialsDirectory(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	f := File{Path: "/nonexistent/path"}
	_, err := f.Fetch(context.Background(), "file://validator1")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want an error that wraps fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent/path") {
		t.Fatalf("got %v, want the error for the configured path", err)
	}
}

func TestChainDispatch(t *testing.T) {
	p := writeSecrets(t, `validator1 = "word1 word2"`+"\n", 0o600)
	c := Chain{File: &File{Path: p}}
	if _, err := c.Fetch(context.Background(), "op://vault/item/field"); err == nil {
		t.Fatal("expected error: onepassword not configured")
	}
	v, err := c.Fetch(context.Background(), "file://validator1")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "word1 word2" {
		t.Fatalf("got %q", v)
	}
	if _, err := c.Fetch(context.Background(), "bogus://x"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}
