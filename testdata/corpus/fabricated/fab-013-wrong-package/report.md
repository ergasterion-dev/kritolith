# Cardinality blowup in prometheus/client_golang httpmetrics

prometheus/client_golang v1.19.1: `InstrumentHandlerCounter` in the
`github.com/prometheus/client_golang/prometheus/httpmetrics` package increments a counter
labelled with the raw request path, so an attacker who requests many distinct paths can
create unbounded time series and exhaust the exporter's memory.

Impact: memory exhaustion of the metrics endpoint via label cardinality.
