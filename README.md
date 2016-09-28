# Circonus WireLatency

These are go-based tools to sniff the wire and reconstruct various protocol
sessions to extract various telemetry (namely latency) from transactions
within those sessions.

For example, it can be used to track the latency of HTTP API endpoints.

All telemetry data is pushed up to Circonus.

## Tooling

```
protocol_observer --apitoken <circonus_api_token> -wire <description>
```

The `-wire` flag can be specified multiple times to specify multiple
"wirings."  This is useful if you have multiple ports in use for a
service.  It is recommended to keep separate services monitored by
separate protocol_observer instances.

### Cassandra

```
protocol_observer -apitoken <token> -wire cassandra_cql
```

Will listen on port 9042 for Cassandra CQL framing and disset sessions.
Each request/response will be tracked for latency.  Queries will generically
be tracked as "QUERY", however each prepared query will get its own
metric named for the CQL.  Latency is tracked on each operation as well
as request and response sizes in bytes.

### HTTP

```
protocol_observer -apitoken <token> -wire http:8092:routes.json
```

This will listen for HTTP traffic on port 8092 using the file `routes.json`
as a mapping of URLs to "names."  This allows requests to an API service
to be correctly categorized by endpoint.  See the same routes.json included.

Each request is recorded and the request and response payload sizes are
recorded along with the latency to the first byte of the response and the
latency for the entire respnose.

Metric names are formed as ``<method>`<endpoint>`<status>`` where status is
the HTTP status codes by the hundreds: 1xx, 2xx, 3xx, 4xx, and 5xx.

### Postgres

```
protocol_observer -apitoken <token> -wire postgres:5432:queries.json
```

This will listen for postgres traffic on port 5432.  If a config is omitted
the default config will be used.  If the port is omitted, 5432 will be used.

The protocol observer here distinguishes between regular queries and the
execution of prepared statements.  All statements are tracked and the
latency, request bytes, response bytes and number of tuples effected is
recorded.  The format of metrics looks like ``<type>`<attribute>``
and ``<type>`SELECT`<attribute>`` where the "SELECT" is taken from the postgres
execute command complete packet.  "SELECT" could be "DELETE" or "UPDATE" or
anything else Postgres elects to respond with.  The `<type>` will be one of
Query or Execute.  The `<attribute>` will be one of "latency", "request_bytes",
"response_bytes", or "response_rows."

Additionally, pursuant to your configuration (if supplied) you can record
metrics for a query.  Prepared and Adhoc queries are handeld separately as
most people will only want to record latency information on a limited keyspace
and thus only leverage the configuration to log prepared queries.

The Query field is a regular expression matching against the query being
executed.  The Name field helps instruct how the query should be presented.
If name is an empty string, no query-specific recording is done.  If it is the
string "RAW" then the whole query is jammed int he metric name.  If it is the
string "SHA256" then a hex-encoded sha256 of the query is used.  Otherwise
the literal string is used to build the metric name.

### Kafka

```
protocol_observer -apitoken <token> -wire kafka:9093
```

This will listen for kafka traffic on the specified port (9092 by default).

Message and protocol command latency is recorded as well as message and frame
sizes.  All production "Produce" and consumption "Fetch" are tracked in
`_aggregate` and by topic.  Messages in production and consumption are expanded
(including gzip and snappy) to analyize for message timestamps (for latency) and
uncompressed payload sizes.


# Installation

Installation assuming a working installation of go:

- go executable is on `$PATH`
- `$GOPATH` is set

Tested with go version 1.7.1 on 2016-09-28.

## Ubuntu 12.04

Installation:
```
sudo apt-get install libpcap-dev # need pcap.h
go get github.com/circonus-labs/wirelatency
```

Running:
```
cd $GOPATH/src/github.com/circonus-labs/wirelatency/protocol_observer
sudo go run protocol-observer.go  <options>
```
