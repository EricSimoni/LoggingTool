from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass
class DatabaseConfig:
    host: str
    port: int
    database: str
    user: str
    password: str


@dataclass
class GeoIPConfig:
    database_path: str


@dataclass
class CollectorConfig:
    schema: str
    table: str
    batch_size: int


@dataclass
class AppConfig:
    database: DatabaseConfig
    geoip: GeoIPConfig
    collector: CollectorConfig


def load_config(path="config/config.yaml") -> AppConfig:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}. Copy config/config.example.yaml to config/config.yaml."
        )

    with path.open() as fh:
        data = yaml.safe_load(fh)

    # TODO: Add environment-variable support and stronger validation.
    return AppConfig(
        database=DatabaseConfig(**data["database"]),
        geoip=GeoIPConfig(**data["geoip"]),
        collector=CollectorConfig(**data["collector"]),
    )
