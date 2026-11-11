package verdict

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	keyDirName     = "keys"
	privateKeyName = "verdict-signing.key"
	publicKeyName  = "verdict-signing.pub"
	seedPrefix     = "kritolith-ed25519-seed:"
)

// KeyPaths returns where the signing key pair lives under dataDir. The
// keys sit in their own directory, apart from the database and the git
// mirrors, so the data can be backed up or mounted without the key.
func KeyPaths(dataDir string) (private, public string) {
	dir := filepath.Join(dataDir, keyDirName)
	return filepath.Join(dir, privateKeyName), filepath.Join(dir, publicKeyName)
}

// GenerateKey creates a new signing key pair under dataDir, reading
// randomness from rnd, and returns the public key. It never replaces
// an existing key: verdicts already signed with it would stop
// verifying against what `keygen` prints.
func GenerateKey(dataDir string, rnd io.Reader) (ed25519.PublicKey, error) {
	if dataDir == "" {
		return nil, errors.New("verdict: keygen: data dir is empty")
	}
	privPath, pubPath := KeyPaths(dataDir)
	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("verdict: keygen: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("verdict: keygen: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, fmt.Errorf("verdict: keygen: %w", err)
	}
	// O_EXCL makes "create only if absent" one atomic step, and
	// O_NOFOLLOW refuses a symlink planted at the path.
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("verdict: keygen: %s already exists; refusing to replace a signing key", privPath)
	}
	if err != nil {
		return nil, fmt.Errorf("verdict: keygen: %w", err)
	}
	line := seedPrefix + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		os.Remove(privPath)
		return nil, fmt.Errorf("verdict: keygen: write %s: %w", privPath, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(privPath)
		return nil, fmt.Errorf("verdict: keygen: write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, []byte(FormatPublicKey(pub)+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("verdict: keygen: write %s: %w", pubPath, err)
	}
	return pub, nil
}

// LoadKey reads the signing key under dataDir. found is false, with no
// error, when no key has been generated: signing is optional. A key
// file that exists but is readable by group or others, is a symlink,
// or doesn't parse is an error, never silently "no key".
func LoadKey(dataDir string) (key ed25519.PrivateKey, found bool, err error) {
	privPath, _ := KeyPaths(dataDir)
	f, err := os.OpenFile(privPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, false, fmt.Errorf("verdict: %s is a symlink; refusing to use it", privPath)
	}
	if err != nil {
		return nil, false, fmt.Errorf("verdict: read signing key: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("verdict: read signing key: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("verdict: %s is not a regular file", privPath)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return nil, false, fmt.Errorf("verdict: signing key %s has mode %v; it must not be accessible by group or others (run: chmod 600 %s)", privPath, perm, privPath)
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, false, fmt.Errorf("verdict: read signing key: %w", err)
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(string(data)), seedPrefix)
	if !ok {
		return nil, false, fmt.Errorf("verdict: %s is not a Kritolith signing key", privPath)
	}
	seed, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("verdict: %s is not a Kritolith signing key", privPath)
	}
	return ed25519.NewKeyFromSeed(seed), true, nil
}

// LoadPublicKey reads the public key file under dataDir.
func LoadPublicKey(dataDir string) (ed25519.PublicKey, error) {
	_, pubPath := KeyPaths(dataDir)
	return ReadPublicKeyFile(pubPath)
}

// ReadPublicKeyFile reads a file holding one "ed25519:<base64>" line.
func ReadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("verdict: read public key: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, fmt.Errorf("verdict: read public key: %w", err)
	}
	pub, err := ParsePublicKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, path)
	}
	return pub, nil
}
