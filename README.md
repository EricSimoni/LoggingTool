# Intrusion Logger

A Python tool for collecting firewall connection attempts from PostgreSQL, geolocating source IPs, and enriching the data for security analysis.

## Features

- **Firewall Log Collection**: Retrieves raw firewall events from PostgreSQL database populated by rsyslog
- **IP Geolocation**: Uses MaxMind GeoLite2 database to enrich events with geographic information
- **Modular Architecture**: Clean separation between database access, collection, geolocation, and processing
- **Type Safety**: Full type hints and dataclass-based models for reliable data handling
- **Configurable**: YAML-based configuration with environment-specific settings

## Data Flow

```
firewalld/nftables
    ↓
rsyslog
    ↓
PostgreSQL (eng_ops.firewall_logs)
    ↓
Python Collector
    ↓
GeoIP Enrichment
    ↓
PostgreSQL (eng_ops.firewall_event_enrichment)
    ↓
Future: API/Dashboard
```

## Requirements

- Python 3.10+
- PostgreSQL with firewall logs
- MaxMind GeoLite2 City database
- Fedora Linux (rsyslog + firewalld configuration)

## Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install package in editable mode (required for proper module resolution)
pip install -e .

# Copy and configure
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your database credentials
```

## Database Setup

For complete Fedora-specific setup instructions including PostgreSQL, pgAdmin, and rsyslog configuration, see [docs/FEDORA_SETUP.md](docs/FEDORA_SETUP.md).

**Quick setup steps:**

1. **Apply the base table schema**:
```bash
psql -U postgres -d intrusion -f sql/000_base_table.sql
```

2. **Apply the enrichment table schema**:
```bash
psql -U postgres -d intrusion -f sql/001_enrichment_table.sql
```

3. **Configure rsyslog** to log firewalld events to PostgreSQL (see [docs/FEDORA_SETUP.md](docs/FEDORA_SETUP.md) for complete rsyslog configuration)

## Configuration

Edit `config/config.yaml`:

```yaml
database:
  host: "127.0.0.1"
  port: 5432
  database: "intrusion"
  user: "intrusion_logger"
  password: "your_password"

geoip:
  database_path: "/usr/share/GeoIP/GeoLite2-City.mmdb"
  enabled: true

collector:
  source: "/var/log/firewall.log"
  poll_interval: 5

processor:
  batch_size: 100
  enrich: true
```

## Usage

```bash
# Show help
python -m intrusion_logger --help

# Process one batch of unprocessed events
python -m intrusion_logger --once

# Continuous mode (not yet implemented)
python -m intrusion_logger
```

## Architecture

The project is organized into modular components:

- **`database.py`**: PostgreSQL connection and query execution using psycopg
- **`collector.py`**: Retrieves raw firewall events from the database
- **`geolocation.py`**: IP address geolocation using MaxMind GeoIP2
- **`processor.py`**: Event enrichment and classification
- **`models.py`**: Data models for firewall events and geolocation data
- **`config.py`**: Configuration loading and validation

## Development

```bash
# Run tests
pytest

# The prototype folder contains the original database setup and rsyslog configuration
# for Fedora systems. It is excluded from git via .gitignore
```

## Security Notes

- Never commit `config/config.yaml` to version control
- Never commit database passwords or API keys
- Keep GeoIP database files out of version control
- Use dedicated PostgreSQL roles with minimum required privileges
- Treat all network data as untrusted input

## License

This project is provided as-is for security monitoring and analysis purposes.
