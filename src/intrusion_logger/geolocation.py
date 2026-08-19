"""GeoIP enrichment for firewall events."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import geoip2.database
import geoip2.errors

from .models import GeoLocation, IPAddress


class GeoLocationError(RuntimeError):
    """Base exception for GeoIP-related errors."""


class GeoLocator:
    """Look up geographic information for IP addresses.

    This class only handles GeoIP lookups. It does not access
    PostgreSQL and does not modify FirewallEvent objects.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self._reader: geoip2.database.Reader | None = None

    def open(self) -> None:
        """Open the GeoIP database."""

        if self._reader is not None:
            return

        if not self.database_path.is_file():
            raise GeoLocationError(
                f"GeoIP database not found: "
                f"{self.database_path}"
            )

        try:
            self._reader = geoip2.database.Reader(
                str(self.database_path)
            )
        except Exception as exc:
            raise GeoLocationError(
                "Unable to open GeoIP database."
            ) from exc

    def close(self) -> None:
        """Close the GeoIP database."""

        if self._reader is not None:
            self._reader.close()
            self._reader = None

    @property
    def reader(self) -> geoip2.database.Reader:
        """Return the active GeoIP reader."""

        if self._reader is None:
            raise GeoLocationError(
                "GeoIP database is not open. "
                "Call open() first."
            )

        return self._reader

    def lookup(
        self,
        ip: IPAddress | str,
    ) -> GeoLocation | None:
        """Look up geographic information for an IP address.

        Parameters
        ----------
        ip:
            IPv4 or IPv6 address, either as an ipaddress object
            or a string.

        Returns
        -------
        GeoLocation | None
            GeoIP information when the address exists in the
            database. Returns None when the address has no
            available GeoIP record.
        """

        try:
            if isinstance(ip, str):
                address = IPv4Address(ip) if "." in ip else IPv6Address(ip)
            else:
                address = ip

        except ValueError as exc:
            raise GeoLocationError(
                f"Invalid IP address: {ip!r}"
            ) from exc

        try:
            response = self.reader.city(address)

        except geoip2.errors.AddressNotFoundError:
            return None

        except geoip2.errors.GeoIP2Error as exc:
            raise GeoLocationError(
                f"GeoIP lookup failed for {address}."
            ) from exc

        return GeoLocation(
            ip=str(address),
            city=response.city.name,
            region=response.subdivisions.most_specific.name,
            country=response.country.name,
            latitude=response.location.latitude,
            longitude=response.location.longitude,
            postal=response.postal.code,
            timezone=response.location.time_zone,
        )

    def __enter__(self) -> GeoLocator:
        """Open the GeoIP database as a context manager."""

        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        """Close the GeoIP database when leaving a context manager."""

        self.close()