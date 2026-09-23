package main

import (
	"flag"
	"path/filepath"

	"github.com/ergasterion-dev/kritolith/internal/config"
)

// parseInterspersed parses flags that may appear before or after
// positional arguments ("check report.md --poc dir"), which the flag
// package alone doesn't allow. It returns the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// resolveDataDir picks the data dir: --data-dir, then data_dir from cfg
// (the already-loaded --config, if any), then the platform default.
// It never loads --config itself: the caller must always load --config
// when given, even if --data-dir also is, so a broken --config is never
// silently ignored.
func resolveDataDir(flagDir string, cfg *config.Config) (string, error) {
	if flagDir != "" {
		return filepath.Abs(flagDir)
	}
	if cfg != nil && cfg.DataDir != "" {
		return cfg.DataDir, nil
	}
	return config.DefaultDataDir()
}
