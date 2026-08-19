from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias


IPAddress: TypeAlias = IPv4Address | IPv6Address


@dataclass(slots=True)
class FirewallEvent:
    """A raw firewall event collected from PostgreSQL.

    This represents an event as it exists inside the Python
    application. It does not contain enrichment or classification
    information.
    """

    id: int
    log_time: datetime

    src_ip: IPAddress
    dst_ip: IPAddress | None

    protocol: str | None

    src_port: int | None
    dst_port: int | None

    action: str | None
    message: str | None


@dataclass(slots=True)
class GeoLocation:
    """GeoIP information associated with an IP address.

    Any field other than ``ip`` may be unavailable depending on
    the information contained in the GeoIP database.
    """

    ip: str

    city: str | None
    region: str | None
    country: str | None

    latitude: float | None
    longitude: float | None

    postal: str | None
    timezone: str | None