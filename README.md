# Intrusion Logger

Python tool for reading firewall connection attempts from PostgreSQL, geolocating
source IPs, and eventually exposing the results to a dashboard/API.

## Data flow

rsyslog + firewalld -> PostgreSQL (`intrusion.eng_ops.firewall_logs`)
-> Python collector -> GeoIP enrichment -> enrichment table -> API/dashboard

This template is intentionally incomplete. The TODOs mark the parts you should
implement as the project develops.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
python -m src.intrusion_logger --help
```

Do not commit `config/config.yaml`, passwords, `.env` files, or GeoIP databases.
