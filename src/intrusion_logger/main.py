import argparse
import logging
import pprint
import sys

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
    parser.add_argument(
        "--tablename",
        help="Specify a table name for operations"
    )
    parser.add_argument(
        "--dump_table",
        action="store_true",
        help="Dump the firewall log table to stdout"
    )
    parser.add_argument(
        "--geolocate_ip",
        action="store_true",
        help="Geolocate IPs from the firewall log"
    )
    parser.add_argument(
        "--filename", "-f",
        help="Text file with list of server names or IP addresses, one per line"
    )
    parser.add_argument(
        "--config", "-c",
        default="config/config.yaml",
        help="Path to configuration file (default: config/config.yaml)"
    )
    parser.add_argument(
        "--loglevel", "-l", 
        default="INFO",
        help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        help="Increase verbosity (can be used multiple times)"
    )
    parser.add_argument(
        "--debug", "-d", 
        action="store_true", 
        help="Turn on debugging output"
    )
    parser.add_argument(
        "--version", "-V", 
        action="version", 
        version="%(prog)s 0.1.0"
    )
    return parser


def main():
    args = build_parser().parse_args()
    
    if len(sys.argv) <= 1:
        print("Not enough arguments. Use -h for help")
        sys.exit(1)
    
    config = load_config(args.config)
    
    # Setup logging
    log_level = getattr(logging, args.loglevel.upper(), logging.INFO)
    if args.debug:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format=config.logging.format
    )
    logger = logging.getLogger(__name__)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Initialize components - they handle their own connections
    db = Database(config.database)
    collector = FirewallLogCollector(db, config.collector)
    geolocator = GeoLocator(config.geoip.database_path)

    if args.dump_table:
        firewall_log_dict = collector.dump_all_logs()
        pprint.pprint(firewall_log_dict)
        collector.close()
        sys.exit(0)

    if args.geolocate_ip:
        firewall_log_dict = collector.dump_all_logs()
        for key, value in firewall_log_dict.items():
            src_ip = value.get("src_ip")
            if src_ip:
                geolocation = geolocator.lookup(src_ip)
                if geolocation:
                    print(f"{src_ip=} country={geolocation.country} region={geolocation.region}")
                else:
                    print(f"{src_ip=} country=None region=None (not found in GeoIP database)")
        collector.close()
        sys.exit(0)

    if args.tablename:
        row_count = collector.count_table_rows(args.tablename)
        print(f"Total count of rows in {args.tablename}: {row_count}")
        collector.close()
        sys.exit(0)

    if args.filename:
        # Read file and geolocate each IP address
        try:
            with open(args.filename, 'r') as f:
                for line in f:
                    ip_address = line.strip()
                    if ip_address:
                        geolocation = geolocator.lookup(ip_address)
                        if geolocation:
                            print(f"{ip_address=} country={geolocation.country} region={geolocation.region}")
                        else:
                            print(f"{ip_address=} country=None region=None (not found in GeoIP database)")
        except FileNotFoundError:
            print(f"Error: File not found: {args.filename}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.once:
        events = collector.fetch_unprocessed()
        for event in events:
            result = geolocator.lookup(event.src_ip)
            print(result)
        collector.close()
        return

    print("Continuous mode is not implemented yet. Use --once for the prototype.")
    collector.close()


if __name__ == "__main__":
    main()
