import argparse
import logging
import logging.config
import logging.handlers
import platform
import pprint
import sys
from pathlib import Path

import psutil

from . import __version__
from .config import load_config
from .database import Database
from .collector import FirewallLogCollector
from .geolocation import GeoLocator
from .web import app
from .graphing import (
    aggregate_activity_data,
    aggregate_country_data,
    aggregate_port_data,
    aggregate_protocol_data,
    aggregate_action_data,
    export_data_csv,
    export_data_json,
    export_data_yaml,
    parse_time_range,
)


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
        help="Path to configuration file",
        default="config/config.yaml"
    )
    parser.add_argument(
        "--logging-config",
        help="Path to logging configuration file",
        default="config/logging_config.ini"
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
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics (row counts, storage size, etc.)"
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Run health checks (database, GeoIP, config)"
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Display current configuration"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show quick summary of firewall logs"
    )
    parser.add_argument(
        "--recent",
        type=int,
        metavar="N",
        help="Show last N log entries"
    )
    parser.add_argument(
        "--top-ips",
        type=int,
        metavar="N",
        help="Show top N source IPs by request count"
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Show most targeted destination ports"
    )
    parser.add_argument(
        "--by-action",
        metavar="ACTION",
        help="Show logs filtered by action type (ALLOW/DENY/REJECT)"
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM on the database table"
    )
    parser.add_argument(
        "--retention-status",
        action="store_true",
        help="Show retention policy status"
    )
    parser.add_argument(
        "--test-geoip",
        metavar="IP",
        help="Test GeoIP lookup with a specific IP address"
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration file without running"
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the web dashboard server"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind web server to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run web server on (default: 8000)"
    )
    parser.add_argument(
        "--os-info",
        action="store_true",
        help="Display operating system information"
    )
    return parser


def main():
    args = build_parser().parse_args()
    
    if len(sys.argv) <= 1:
        print("Not enough arguments. Use -h for help")
        sys.exit(1)
    
    config = load_config(args.config)
    
    # Display OS information if requested
    if args.os_info:
        print("Operating System Information:")
        print("-" * 40)
        print(f"System: {platform.system()}")
        print(f"Node Name: {platform.node()}")
        print(f"Release: {platform.release()}")
        print(f"Version: {platform.version()}")
        print(f"Machine: {platform.machine()}")
        print(f"Processor: {platform.processor()}")
        print(f"Python Version: {platform.python_version()}")
        print(f"Python Implementation: {platform.python_implementation()}")
        print()
        print("Memory Information:")
        print("-" * 40)
        mem = psutil.virtual_memory()
        print(f"Total Memory: {mem.total / (1024**3):.2f} GB")
        print(f"Available Memory: {mem.available / (1024**3):.2f} GB")
        print(f"Used Memory: {mem.used / (1024**3):.2f} GB")
        print(f"Memory Percentage: {mem.percent:.1f}%")
        print()
        print("CPU Information:")
        print("-" * 40)
        print(f"CPU Count: {psutil.cpu_count(logical=False)} physical, {psutil.cpu_count(logical=True)} logical")
        print(f"CPU Usage: {psutil.cpu_percent(interval=1):.1f}%")
        sys.exit(0)
    
    # Start web server if requested
    if args.serve:
        import uvicorn
        logger.info(f"Starting web server on {args.host}:{args.port}")
        print(f"Starting web dashboard on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
        sys.exit(0)
    
    # Set up logging from config file
    # Create logs directory first
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Load logging configuration from INI file
    logging_config_path = Path(args.logging_config)
    if logging_config_path.exists():
        logging.config.fileConfig(logging_config_path, disable_existing_loggers=False)
    else:
        # Fallback to basic config if file doesn't exist
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.handlers.RotatingFileHandler(
                    log_dir / "intrusion_logger.log",
                    maxBytes=10 * 1024 * 1024,
                    backupCount=5
                )
            ]
        )
    
    # Override log level if debug flag is set
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)
    
    logger = logging.getLogger(__name__)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info(f"Intrusion Logger version {__version__} starting")
    logger.debug(f"Configuration loaded from: {args.config}")
    logger.debug(f"Logging configuration loaded from: {args.logging_config}")

    # Initialize components - they handle their own connections
    db = Database(config.database)
    collector = FirewallLogCollector(db, config.collector)
    geolocator = GeoLocator(config.geoip.database_path)

    if args.validate_config:
        print("Configuration validation:")
        print("-" * 40)
        print(f"Config file: {args.config}")
        print(f"Database host: {config.database.host}")
        print(f"Database name: {config.database.database}")
        print(f"GeoIP database: {config.geoip.database_path}")
        print(f"Collector schema: {config.collector.schema}")
        print(f"Collector table: {config.collector.table}")
        print(f"Retention enabled: {config.retention.enabled}")
        print(f"Retention max days: {config.retention.max_days}")
        print("\nConfiguration appears valid.")
        sys.exit(0)

    if args.show_config:
        print("Current configuration:")
        print("-" * 40)
        print(f"Environment: {config.environment}")
        print(f"\nDatabase:")
        print(f"  Host: {config.database.host}")
        print(f"  Port: {config.database.port}")
        print(f"  Database: {config.database.database}")
        print(f"  User: {config.database.user}")
        print(f"  Schema: {config.database.schema}")
        print(f"\nGeoIP:")
        print(f"  Database path: {config.geoip.database_path}")
        print(f"  Enabled: {config.geoip.enabled}")
        print(f"\nCollector:")
        print(f"  Schema: {config.collector.schema}")
        print(f"  Table: {config.collector.table}")
        print(f"  Batch size: {config.collector.batch_size}")
        print(f"\nRetention:")
        print(f"  Enabled: {config.retention.enabled}")
        print(f"  Max days: {config.retention.max_days}")
        sys.exit(0)

    if args.test_geoip:
        test_ip = args.test_geoip
        print(f"Testing GeoIP lookup for: {test_ip}")
        try:
            geolocation = geolocator.lookup(test_ip)
            if geolocation:
                print(f"Country: {geolocation.country}")
                print(f"Region: {geolocation.region}")
                print(f"City: {geolocation.city}")
            else:
                print("No geolocation data found for this IP")
        except Exception as exc:
            print(f"GeoIP lookup failed: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.health:
        print("Health checks:")
        print("-" * 40)
        
        # Database connection
        try:
            db.connect()
            print("✓ Database connection: OK")
            db.close()
        except Exception as exc:
            print(f"✗ Database connection: FAILED - {exc}")
            sys.exit(1)
        
        # GeoIP database
        try:
            if config.geoip.database_path.exists():
                print("✓ GeoIP database file: OK")
            else:
                print(f"✗ GeoIP database file: NOT FOUND - {config.geoip.database_path}")
                sys.exit(1)
        except Exception as exc:
            print(f"✗ GeoIP database check: FAILED - {exc}")
            sys.exit(1)
        
        # Config
        print("✓ Configuration: OK")
        
        print("\nAll health checks passed.")
        collector.close()
        sys.exit(0)

    if args.stats:
        print("Database Statistics:")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        
        # Row count
        try:
            count = collector.count_table_rows(table)
            print(f"Row count: {count}")
        except Exception as exc:
            logger.error(f"Failed to get row count: {exc}")
            print(f"Row count: Error - {exc}")
        
        # Storage size
        try:
            sql = f"""
                SELECT pg_size_pretty(pg_total_relation_size('{table}')) as size
            """
            result = db.fetch_one(sql)
            if result:
                print(f"Storage size: {result['size']}")
        except Exception as exc:
            logger.error(f"Failed to get storage size: {exc}")
            print(f"Storage size: Error - {exc}")
        
        # Oldest and newest entries
        try:
            sql = f"""
                SELECT MIN(log_time) as oldest, MAX(log_time) as newest
                FROM {table}
            """
            result = db.fetch_one(sql)
            if result:
                print(f"Oldest entry: {result['oldest']}")
                print(f"Newest entry: {result['newest']}")
        except Exception as exc:
            logger.error(f"Failed to get time range: {exc}")
            print(f"Time range: Error - {exc}")
        
        collector.close()
        sys.exit(0)

    if args.summary:
        print("Firewall Log Summary:")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        
        # Total count grouped by action
        try:
            sql = f"""
                SELECT action, COUNT(*) as count
                FROM {table}
                GROUP BY action
                ORDER BY count DESC
            """
            results = db.fetch_all(sql)
            if results:
                print("\nBy action:")
                for row in results:
                    print(f"  {row['action']}: {row['count']}")
        except Exception as exc:
            logger.error(f"Failed to get action summary: {exc}")
            print(f"Action summary: Error - {exc}")
        
        # Top 5 source IPs
        try:
            sql = f"""
                SELECT src_ip, COUNT(*) as count
                FROM {table}
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 5
            """
            results = db.fetch_all(sql)
            if results:
                print("\nTop 5 source IPs:")
                for row in results:
                    print(f"  {row['src_ip']}: {row['count']}")
        except Exception as exc:
            logger.error(f"Failed to get top IPs: {exc}")
            print(f"Top IPs: Error - {exc}")
        
        # Top 5 destination ports
        try:
            sql = f"""
                SELECT dport, COUNT(*) as count
                FROM {table}
                WHERE dport IS NOT NULL
                GROUP BY dport
                ORDER BY count DESC
                LIMIT 5
            """
            results = db.fetch_all(sql)
            if results:
                print("\nTop 5 destination ports:")
                for row in results:
                    print(f"  {row['dport']}: {row['count']}")
        except Exception as exc:
            logger.error(f"Failed to get top ports: {exc}")
            print(f"Top ports: Error - {exc}")
        
        collector.close()
        sys.exit(0)

    if args.retention_status:
        print("Retention Policy Status:")
        print("-" * 40)
        print(f"Enabled: {config.retention.enabled}")
        print(f"Max days: {config.retention.max_days}")
        
        table = f"{config.collector.schema}.{config.collector.table}"
        
        # Check how many rows would be deleted
        try:
            sql = f"""
                SELECT COUNT(*) as count
                FROM {table}
                WHERE log_time < NOW() - INTERVAL '{config.retention.max_days} days'
            """
            result = db.fetch_one(sql)
            if result:
                print(f"Rows older than {config.retention.max_days} days: {result['count']}")
        except Exception as exc:
            logger.error(f"Failed to check retention status: {exc}")
            print(f"Retention check: Error - {exc}")
        
        # Current storage size
        try:
            sql = f"""
                SELECT pg_size_pretty(pg_total_relation_size('{table}')) as size
            """
            result = db.fetch_one(sql)
            if result:
                print(f"Current storage size: {result['size']}")
        except Exception as exc:
            logger.error(f"Failed to get storage size: {exc}")
            print(f"Storage size: Error - {exc}")
        
        collector.close()
        sys.exit(0)

    if args.vacuum:
        print("Running VACUUM on database table...")
        table = f"{config.collector.schema}.{config.collector.table}"
        try:
            sql = f"VACUUM {table}"
            db.execute(sql)
            print(f"VACUUM completed on {table}")
        except Exception as exc:
            logger.error(f"VACUUM failed: {exc}")
            print(f"VACUUM failed: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.recent:
        n = args.recent
        print(f"Last {n} log entries:")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        try:
            sql = f"""
                SELECT * FROM {table}
                ORDER BY log_time DESC
                LIMIT {n}
            """
            results = db.fetch_all(sql)
            if results:
                for row in results:
                    print(f"{row['log_time']}: {row['src_ip']} -> {row['dst_ip']}:{row['dport']} ({row['action']})")
            else:
                print("No log entries found")
        except Exception as exc:
            logger.error(f"Failed to fetch recent logs: {exc}")
            print(f"Error: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.top_ips:
        n = args.top_ips
        print(f"Top {n} source IPs by request count:")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        try:
            sql = f"""
                SELECT src_ip, COUNT(*) as count
                FROM {table}
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT {n}
            """
            results = db.fetch_all(sql)
            if results:
                for row in results:
                    print(f"{row['src_ip']}: {row['count']} requests")
            else:
                print("No log entries found")
        except Exception as exc:
            logger.error(f"Failed to fetch top IPs: {exc}")
            print(f"Error: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.top_ports:
        n = args.top_ports
        print(f"Top {n} destination ports:")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        try:
            sql = f"""
                SELECT dport, COUNT(*) as count
                FROM {table}
                WHERE dport IS NOT NULL
                GROUP BY dport
                ORDER BY count DESC
                LIMIT {n}
            """
            results = db.fetch_all(sql)
            if results:
                for row in results:
                    print(f"Port {row['dport']}: {row['count']} hits")
            else:
                print("No log entries found")
        except Exception as exc:
            logger.error(f"Failed to fetch top ports: {exc}")
            print(f"Error: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

    if args.by_action:
        action = args.by_action.upper()
        print(f"Logs with action '{action}':")
        print("-" * 40)
        
        table = f"{config.collector.schema}.{config.collector.table}"
        try:
            sql = f"""
                SELECT * FROM {table}
                WHERE action = '{action}'
                ORDER BY log_time DESC
                LIMIT 20
            """
            results = db.fetch_all(sql)
            if results:
                for row in results:
                    print(f"{row['log_time']}: {row['src_ip']} -> {row['dst_ip']}:{row['dport']}")
                print(f"\nTotal matching entries: {len(results)} (showing first 20)")
            else:
                print(f"No logs found with action '{action}'")
        except Exception as exc:
            logger.error(f"Failed to fetch logs by action: {exc}")
            print(f"Error: {exc}")
            sys.exit(1)
        collector.close()
        sys.exit(0)

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
