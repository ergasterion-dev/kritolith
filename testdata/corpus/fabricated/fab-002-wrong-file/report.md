# Command injection through shell argument expansion in cobra

cobra v1.9.1 expands `$VAR` and backticks in positional arguments before passing
them to `RunE`. The expansion happens in `expandShellArgs` in `shell_expand.go`,
which calls `sh -c` on attacker-controlled argument text.

Any CLI built with cobra that is invoked with untrusted arguments (for example from
a CI job) can be made to execute arbitrary commands.

PoC:

```sh
mycli run '`id > /tmp/pwned`'
```
