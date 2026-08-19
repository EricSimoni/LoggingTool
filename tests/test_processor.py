from datetime import datetime, timezone
from ipaddress import ip_address

from intrusion_logger.models import FirewallEvent, GeoLocation
from intrusion_logger.processor import process_event


class FakeGeoLocator:
    def lookup(self, ip):
        return GeoLocation(
            ip=str(ip),
            city="Test City",
            region="Test Region",
            country="TEST",
            latitude=1.0,
            longitude=2.0,
            postal="12345",
            timezone="UTC",
        )


def test_process_event():
    event = FirewallEvent(
        id=1,
        log_time=datetime.now(timezone.utc),
        src_ip=ip_address("8.8.8.8"),
        dst_ip=ip_address("10.0.0.1"),
        protocol="TCP",
        src_port=12345,
        dst_port=22,
        action="REJECT",
        message="test",
    )

    result = process_event(event, FakeGeoLocator())

    assert result["event_id"] == 1
    assert result["geo"]["country"] == "TEST"
