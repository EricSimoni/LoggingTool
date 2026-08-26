"""GeoIP enrichment for firewall events."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import geoip2.database
import geoip2.errors

from .models import GeoLocation, IPAddress

logger = logging.getLogger(__name__)


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
        logger.info(f"Initializing GeoLocator with database: {self.database_path}")
        self.open()

    def open(self) -> None:
        """Open the GeoIP database."""

        if self._reader is not None:
            logger.debug("GeoIP database already open")
            return

        logger.debug(f"Opening GeoIP database at: {self.database_path}")
        if not self.database_path.is_file():
            logger.error(f"GeoIP database file not found: {self.database_path}")
            raise GeoLocationError(
                f"GeoIP database not found: "
                f"{self.database_path}"
            )

        try:
            self._reader = geoip2.database.Reader(
                str(self.database_path)
            )
            logger.info("Successfully opened GeoIP database")
        except Exception as exc:
            logger.error(f"Failed to open GeoIP database: {exc}")
            raise GeoLocationError(
                "Unable to open GeoIP database."
            ) from exc

    def close(self) -> None:
        """Close the GeoIP database."""

        if self._reader is not None:
            logger.info("Closing GeoIP database")
            self._reader.close()
            self._reader = None
            logger.debug("GeoIP database closed")

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

        logger.debug(f"Looking up geolocation for IP: {ip}")
        try:
            if isinstance(ip, str):
                address = IPv4Address(ip) if "." in ip else IPv6Address(ip)
            else:
                address = ip

        except ValueError as exc:
            logger.error(f"Invalid IP address format: {ip!r}")
            raise GeoLocationError(
                f"Invalid IP address: {ip!r}"
            ) from exc

        try:
            response = self.reader.city(address)
            logger.debug(f"GeoIP lookup successful for {address}: {response.country.name}")

        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP address not found in GeoIP database: {address}")
            return None

        except geoip2.errors.GeoIP2Error as exc:
            logger.error(f"GeoIP lookup failed for {address}: {exc}")
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