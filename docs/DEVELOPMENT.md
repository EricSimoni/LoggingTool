# Development Notes

The original prototype supplied with this project already demonstrates:

- SQLAlchemy/Psycopg2 PostgreSQL connectivity.
- Reading `eng_ops.firewall_logs`.
- Extracting source/destination IPs, ports, and protocol.
- GeoLite2/GeoIP2 lookup.
- CLI operations such as dumping firewall logs and geolocating source IPs.

The template separates those responsibilities into modules.

## Suggested order

1. Make `config/config.yaml` work.
2. Test PostgreSQL connectivity.
3. Implement reliable incremental collection.
4. Apply `sql/001_enrichment_table.sql`.
5. Write enriched records.
6. Add tests for database and processing behavior.
7. Add a continuous worker/service.
8. Add Flask/API/dashboard functionality.
