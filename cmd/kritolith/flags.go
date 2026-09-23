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

// resolveDataDir picks the data dir: --data-dir, then data_dir from
// --config, then the platform default.
func resolveDataDir(flagDir, cfgPath string) (string, error) {
	if flagDir != "" {
		return filepath.Abs(flagDir)
	}
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return "", err
		}
		if cfg.DataDir != "" {
			return cfg.DataDir, nil
		}
	}
	return config.DefaultDataDir()
}
