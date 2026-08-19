# Architecture

```text
                 SERVER
                    |
             firewalld/nftables
                    |
                 rsyslog
                    |
                    v
        PostgreSQL / intrusion
        eng_ops.firewall_logs
                    |
                    | read
                    v
             Python collector
                    |
                    v
              Event model
                    |
                    v
             GeoIP enrichment
                    |
                    v
       enrichment/persistence
                    |
          +---------+---------+
          |                   |
       CLI/report          Flask/API
                              |
                           dashboard
```

## Why separate the enrichment table?

`firewall_logs` is the raw security-event ingestion table. Python should generally
avoid rewriting those records. A separate enrichment table lets you re-run
geolocation/classification later without losing the original event.

## Modules

- `database.py`: PostgreSQL connectivity.
- `collector.py`: retrieves raw firewall events.
- `models.py`: application data structures.
- `geolocation.py`: MaxMind GeoLite2 lookups.
- `processor.py`: enrichment and classification rules.
- `main.py`: CLI entry point.

## Future continuous worker

```text
SELECT new events
       |
       v
process batch
       |
       v
write enrichment
       |
       v
remember last processed ID
       |
       +----> repeat
```

A later version could use PostgreSQL `LISTEN/NOTIFY` if polling becomes a bottleneck.

## Security

- Never commit database passwords.
- Use a dedicated PostgreSQL role with minimum required privileges.
- Treat all network data as untrusted input.
- Use parameterized SQL for values.
- Keep GeoIP databases outside Git.
- Plan for log retention because firewall logs can grow quickly.
