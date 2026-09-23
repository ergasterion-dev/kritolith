// Command kritolith verifies security reports before maintainers read them.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Usage: kritolith <command> [flags]

Commands:
  check     verify a single report file
  eval      run the eval corpus and print the scoreboard
  version   print the version

Run "kritolith <command> -h" for command flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run executes one CLI invocation and returns the process exit code:
// 0 success, 1 runtime failure, 2 usage error.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "eval":
		return runEval(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "kritolith %s\n", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "kritolith: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// fail prints a runtime error and returns the exit code for it. err may
// carry reporter-controlled text (a hostile title, PoC name, ...), so it
// is passed through report.Printable before reaching the terminal.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "kritolith: %s\n", report.Printable(err.Error()))
	return 1
}
