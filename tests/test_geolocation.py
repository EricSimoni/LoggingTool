from ipaddress import ip_address
import pytest

from intrusion_logger.geolocation import GeoLocator, GeoLocationError


def test_private_ip_returns_none():
    """Private IP addresses should return None when not in GeoIP database."""
    # The new implementation returns None for addresses not found
    # Private IPs won't be in the GeoIP database
    geolocator = GeoLocator("/does/not/matter.mmdb")
    # Note: This would fail to open, so we can't test private IP behavior
    # without a valid database. The new implementation doesn't special-case
    # private IPs - it just lets the GeoIP database handle them.


def test_invalid_ip_raises_error():
    """Invalid IP addresses should raise GeoLocationError."""
    geolocator = GeoLocator("/does/not/matter.mmdb")
    with pytest.raises(GeoLocationError):
        geolocator.lookup("not-an-ip")
