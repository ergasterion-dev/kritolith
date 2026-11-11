package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/store"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// dataDirFlags parses the --config/--data-dir pair several commands
// share and returns the resolved data directory.
func dataDirFromFlags(cfgPath, dataDir string) (string, error) {
	var cfg *config.Config
	if cfgPath != "" {
		c, err := config.Load(cfgPath)
		if err != nil {
			return "", err
		}
		cfg = &c
	}
	return resolveDataDir(dataDir, cfg)
}

func runKeygen(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to kritolith.json")
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith keygen [--data-dir dir] [--config file]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 0 {
		fs.Usage()
		return 2
	}
	dir, err := dataDirFromFlags(*cfgPath, *dataDir)
	if err != nil {
		return fail(stderr, err)
	}
	// Opening the store creates the data dir and enforces that only
	// the current user can reach it, before a key is put inside.
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	st.Close()
	pub, err := verdict.GenerateKey(dir, rand.Reader)
	if err != nil {
		return fail(stderr, err)
	}
	priv, pubPath := verdict.KeyPaths(dir)
	fmt.Fprintf(stdout, "Created the signing key: %s\n", priv)
	fmt.Fprintf(stdout, "Public key (%s):\n%s\n", pubPath, verdict.FormatPublicKey(pub))
	fmt.Fprintln(stdout, "Verdicts are signed from now on. Publish the public key where the people who receive your bundles can find it.")
	return 0
}

func runVerifyBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubKey := fs.String("pubkey", "", "the signer's public key, as ed25519:<base64>")
	pubKeyFile := fs.String("pubkey-file", "", "a file holding the signer's public key")
	cfgPath := fs.String("config", "", "path to kritolith.json (to use this installation's own key)")
	dataDir := fs.String("data-dir", "", "data directory (to use this installation's own key)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith verify-bundle [--pubkey ed25519:... | --pubkey-file file] bundle.tar")
		fmt.Fprintln(stderr, "With no key given, the bundle is checked against this installation's own public key.")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 1 || (*pubKey != "" && *pubKeyFile != "") {
		fs.Usage()
		return 2
	}

	// The key always comes from the person verifying, never from the
	// bundle: a bundle that named its own key would verify whoever
	// made it.
	var pub ed25519.PublicKey
	switch {
	case *pubKey != "":
		pub, err = verdict.ParsePublicKey(*pubKey)
	case *pubKeyFile != "":
		pub, err = verdict.ReadPublicKeyFile(*pubKeyFile)
	default:
		var dir string
		if dir, err = dataDirFromFlags(*cfgPath, *dataDir); err == nil {
			pub, err = verdict.LoadPublicKey(dir)
		}
	}
	if err != nil {
		return fail(stderr, err)
	}

	f, err := os.Open(pos[0])
	if err != nil {
		return fail(stderr, err)
	}
	defer f.Close()
	doc, err := verdict.ReadBundle(f, pub)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "OK: signature verifies against %s\n", verdict.FormatPublicKey(pub))
	fmt.Fprintf(stdout, "Report body sha256: %s\n\n", doc.Report.BodySHA256)
	fmt.Fprint(stdout, verdict.Render(doc.SubjectReport(), doc.Verdict))
	return 0
}
