import argparse

from .config import load_config
from .database import Database
from .collector import FirewallLogCollector
from .geolocation import GeoLocator


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect and geolocate firewall events."
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Process one batch and exit."
    )
    return parser


def main():
    args = build_parser().parse_args()
    config = load_config()

    db = Database(config.database)
    db.connect()
    collector = FirewallLogCollector(db, config.collector)
    
    geolocator = GeoLocator(config.geoip.database_path)
    geolocator.open()

    if args.once:
        events = collector.fetch_unprocessed()
        for event in events:
            print(geolocator.lookup(event.src_ip))
        return

    print("Continuous mode is not implemented yet. Use --once for the prototype.")


if __name__ == "__main__":
    main()
