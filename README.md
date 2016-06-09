# Circonus WireLatency

These are go-based tools to sniff the wire and reconstruct various protocol
sessions to extract various telemetry (namely latency) from trasnactions
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
