from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class DatabaseConfig:
    """PostgreSQL connection configuration."""

    host: str
    port: int = 5432
    database: str = ""
    user: str = ""
    password: str = ""
    schema: str = "public"

    @property
    def sqlalchemy_url(self) -> str:
        """Return a SQLAlchemy PostgreSQL connection URL."""

        return (
            f"postgresql+psycopg2://"
            f"{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )


@dataclass(frozen=True)
class GeoIPConfig:
    """GeoIP database configuration."""

    database_path: Path = Path(
        "/usr/share/GeoIP/GeoLite2-City.mmdb"
    )

    enabled: bool = True


@dataclass(frozen=True)
class LoggingConfig:
    """Application logging configuration."""

    level: str = "INFO"
    format: str = (
        "%(asctime)s %(levelname)s "
        "%(name)s %(message)s"
    )


@dataclass(frozen=True)
class CollectorConfig:
    """Configuration for the log collector."""

    source: str = ""
    poll_interval: int = 5


@dataclass(frozen=True)
class ProcessorConfig:
    """Configuration for intrusion processing."""

    batch_size: int = 100
    enrich: bool = True


@dataclass(frozen=True)
class AppConfig:
    """Top-level application configuration."""

    environment: str = "development"

    database: DatabaseConfig = field(
        default_factory=DatabaseConfig
    )

    geoip: GeoIPConfig = field(
        default_factory=GeoIPConfig
    )

    logging: LoggingConfig = field(
        default_factory=LoggingConfig
    )

    collector: CollectorConfig = field(
        default_factory=CollectorConfig
    )

    processor: ProcessorConfig = field(
        default_factory=ProcessorConfig
    )


def _require_mapping(
    value: Any,
    name: str,
) -> dict[str, Any]:
    """Validate that a YAML section is a mapping."""

    if value is None:
        return {}

    if not isinstance(value, dict):
        raise ValueError(
            f"Configuration section '{name}' "
            "must be a mapping."
        )

    return value


def load_config(path: str | Path) -> AppConfig:
    """
    Load application configuration from a YAML file.

    Parameters
    ----------
    path:
        Path to the YAML configuration file.

    Returns
    -------
    AppConfig
        Parsed application configuration.

    Raises
    ------
    FileNotFoundError
        If the configuration file does not exist.
    ValueError
        If the YAML structure is invalid.
    """

    config_path = Path(path)

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file) or {}

    if not isinstance(raw_config, dict):
        raise ValueError(
            "The top-level configuration must be a YAML mapping."
        )

    database_data = _require_mapping(
        raw_config.get("database"),
        "database",
    )

    geoip_data = _require_mapping(
        raw_config.get("geoip"),
        "geoip",
    )

    logging_data = _require_mapping(
        raw_config.get("logging"),
        "logging",
    )

    collector_data = _require_mapping(
        raw_config.get("collector"),
        "collector",
    )

    processor_data = _require_mapping(
        raw_config.get("processor"),
        "processor",
    )

    database = DatabaseConfig(
        host=str(database_data.get("host", "localhost")),
        port=int(database_data.get("port", 5432)),
        database=str(database_data.get("database", "")),
        user=str(database_data.get("user", "")),
        password=str(database_data.get("password", "")),
        schema=str(database_data.get("schema", "public")),
    )

    geoip = GeoIPConfig(
        database_path=Path(
            geoip_data.get(
                "database_path",
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
            )
        ),
        enabled=bool(
            geoip_data.get("enabled", True)
        ),
    )

    logging_config = LoggingConfig(
        level=str(
            logging_data.get("level", "INFO")
        ).upper(),
        format=str(
            logging_data.get(
                "format",
                LoggingConfig.format,
            )
        ),
    )

    collector = CollectorConfig(
        source=str(
            collector_data.get("source", "")
        ),
        poll_interval=int(
            collector_data.get("poll_interval", 5)
        ),
    )

    processor = ProcessorConfig(
        batch_size=int(
            processor_data.get("batch_size", 100)
        ),
        enrich=bool(
            processor_data.get("enrich", True)
        ),
    )

    return AppConfig(
        environment=str(
            raw_config.get(
                "environment",
                "development",
            )
        ),
        database=database,
        geoip=geoip,
        logging=logging_config,
        collector=collector,
        processor=processor,
    )