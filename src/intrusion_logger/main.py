import argparse
import logging
import logging.handlers
import pprint
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .database import Database
from .collector import FirewallLogCollector
from .geolocation import GeoLocator
from .graphing import (
    aggregate_activity_data,
    aggregate_country_data,
    aggregate_port_data,
    aggregate_protocol_data,
    aggregate_action_data,
    plot_activity_graph,
    plot_country_graph,
    plot_port_graph,
    plot_protocol_graph,
    plot_action_graph,
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
    parser.add_argument(
        "--graph-activity",
        action="store_true",
        help="Generate time series graph of firewall activity"
    )
    parser.add_argument(
        "--graph-countries",
        action="store_true",
        help="Generate bar chart of top source countries"
    )
    parser.add_argument(
        "--graph-ports",
        action="store_true",
        help="Generate chart of most targeted ports"
    )
    parser.add_argument(
        "--graph-protocols",
        action="store_true",
        help="Generate protocol distribution pie chart"
    )
    parser.add_argument(
        "--graph-actions",
        action="store_true",
        help="Generate REJECT/ALLOW/DENY distribution"
    )
    parser.add_argument(
        "--export-graph-data",
        action="store_true",
        help="Export graph data to CSV/JSON for external visualization"
    )
    parser.add_argument(
        "--time-range",
        help="Specify time range for graphs (e.g., '7d', '2024-01-01:2024-01-31')"
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Limit results to top N items (default: 10)"
    )
    parser.add_argument(
        "--output-dir",
        default="graphs",
        help="Directory to save graph files (default: graphs)"
    )
    return parser


def main():
    args = build_parser().parse_args()
    
    if len(sys.argv) <= 1:
        print("Not enough arguments. Use -h for help")
        sys.exit(1)
    
    config = load_config(args.config)
    
    # Set up logging
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    
    # Create logs directory
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(config.logging.format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "intrusion_logger.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(config.logging.format)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    logger = logging.getLogger(__name__)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info(f"Intrusion Logger version {__version__} starting")
    logger.debug(f"Configuration loaded from: {args.config}")
    logger.debug(f"Log level set to: {logging.getLevelName(log_level)}")

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

    # Graphing options
    if any([args.graph_activity, args.graph_countries, args.graph_ports, 
            args.graph_protocols, args.graph_actions, args.export_graph_data]):
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Fetch logs
        logs_list = []
        firewall_log_dict = collector.dump_all_logs()
        for log_id, log_data in firewall_log_dict.items():
            log_entry = {
                'log_time': log_data.get('log_time'),
                'src_ip': log_data.get('src_ip'),
                'dst_ip': log_data.get('dst_ip'),
                'spt': log_data.get('spt'),
                'dport': log_data.get('dport'),
                'protocol': log_data.get('protocol'),
                'action': log_data.get('action'),
            }
            
            # Add geolocation data if available
            src_ip = log_data.get('src_ip')
            if src_ip:
                geolocation = geolocator.lookup(src_ip)
                if geolocation:
                    log_entry['country'] = geolocation.country
                    log_entry['region'] = geolocation.region
                else:
                    log_entry['country'] = 'Unknown'
                    log_entry['region'] = 'Unknown'
            
            logs_list.append(log_entry)
        
        # Apply time range filter if specified
        if args.time_range:
            start_time, end_time = parse_time_range(args.time_range)
            logs_list = [
                log for log in logs_list 
                if start_time <= log['log_time'] <= end_time
            ]
        
        # Generate requested graphs
        if args.graph_activity:
            activity_data = aggregate_activity_data(logs_list)
            plot_activity_graph(activity_data, output_dir / 'activity.png')
            print(f"Activity graph saved to {output_dir / 'activity.png'}")
        
        if args.graph_countries:
            country_data = aggregate_country_data(logs_list, args.top_n)
            plot_country_graph(country_data, output_dir / 'countries.png')
            print(f"Country graph saved to {output_dir / 'countries.png'}")
        
        if args.graph_ports:
            port_data = aggregate_port_data(logs_list, args.top_n)
            plot_port_graph(port_data, output_dir / 'ports.png')
            print(f"Port graph saved to {output_dir / 'ports.png'}")
        
        if args.graph_protocols:
            protocol_data = aggregate_protocol_data(logs_list)
            plot_protocol_graph(protocol_data, output_dir / 'protocols.png')
            print(f"Protocol graph saved to {output_dir / 'protocols.png'}")
        
        if args.graph_actions:
            action_data = aggregate_action_data(logs_list)
            plot_action_graph(action_data, output_dir / 'actions.png')
            print(f"Action graph saved to {output_dir / 'actions.png'}")
        
        # Export data if requested
        if args.export_graph_data:
            if args.graph_activity:
                activity_data = aggregate_activity_data(logs_list)
                export_data_csv(activity_data, output_dir / 'activity_data.csv')
                export_data_json(activity_data, output_dir / 'activity_data.json')
                export_data_yaml(activity_data, output_dir / 'activity_data.yaml')
                print(f"Activity data exported to {output_dir / 'activity_data.csv'}, {output_dir / 'activity_data.json'}, and {output_dir / 'activity_data.yaml'}")
            
            if args.graph_countries:
                country_data = aggregate_country_data(logs_list, args.top_n)
                export_data_csv(country_data, output_dir / 'countries_data.csv')
                export_data_json(country_data, output_dir / 'countries_data.json')
                export_data_yaml(country_data, output_dir / 'countries_data.yaml')
                print(f"Country data exported to {output_dir / 'countries_data.csv'}, {output_dir / 'countries_data.json'}, and {output_dir / 'countries_data.yaml'}")
            
            if args.graph_ports:
                port_data = aggregate_port_data(logs_list, args.top_n)
                export_data_csv(port_data, output_dir / 'ports_data.csv')
                export_data_json(port_data, output_dir / 'ports_data.json')
                export_data_yaml(port_data, output_dir / 'ports_data.yaml')
                print(f"Port data exported to {output_dir / 'ports_data.csv'}, {output_dir / 'ports_data.json'}, and {output_dir / 'ports_data.yaml'}")
            
            if args.graph_protocols:
                protocol_data = aggregate_protocol_data(logs_list)
                export_data_csv(protocol_data, output_dir / 'protocols_data.csv')
                export_data_json(protocol_data, output_dir / 'protocols_data.json')
                export_data_yaml(protocol_data, output_dir / 'protocols_data.yaml')
                print(f"Protocol data exported to {output_dir / 'protocols_data.csv'}, {output_dir / 'protocols_data.json'}, and {output_dir / 'protocols_data.yaml'}")
            
            if args.graph_actions:
                action_data = aggregate_action_data(logs_list)
                export_data_csv(action_data, output_dir / 'actions_data.csv')
                export_data_json(action_data, output_dir / 'actions_data.json')
                export_data_yaml(action_data, output_dir / 'actions_data.yaml')
                print(f"Action data exported to {output_dir / 'actions_data.csv'}, {output_dir / 'actions_data.json'}, and {output_dir / 'actions_data.yaml'}")
        
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
