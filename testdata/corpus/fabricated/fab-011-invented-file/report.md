# Unescaped field values in logrus SyslogFormatter

logrus v1.9.3 seems to allow log injection through `SyslogFormatter.Format` in
`syslog_formatter.go`, which writes field values without neutralising control characters.
A user-controlled field that contains newline characters can add forged lines to the log.

Impact: log forgery / injection wherever this formatter is used with untrusted fields.
