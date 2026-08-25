"""Graphing and data export functionality for firewall logs."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


def parse_time_range(time_range: str) -> tuple[datetime, datetime]:
    """Parse time range string into start and end datetime objects.
    
    Parameters
    ----------
    time_range: str
        Time range in format '7d' (last 7 days) or '2024-01-01:2024-01-31'
        
    Returns
    -------
    tuple[datetime, datetime]
        Start and end datetime objects
    """
    if ':' in time_range:
        # Format: '2024-01-01:2024-01-31'
        start_str, end_str = time_range.split(':')
        start = datetime.fromisoformat(start_str)
        end = datetime.fromisoformat(end_str)
    else:
        # Format: '7d' (last N days)
        if time_range.endswith('d'):
            days = int(time_range[:-1])
            end = datetime.now()
            start = end - timedelta(days=days)
        elif time_range.endswith('h'):
            hours = int(time_range[:-1])
            end = datetime.now()
            start = end - timedelta(hours=hours)
        else:
            raise ValueError(f"Invalid time range format: {time_range}")
    
    return start, end


def aggregate_activity_data(logs: list[dict[str, Any]]) -> pd.DataFrame:
    """Aggregate firewall logs by time for activity graph.
    
    Parameters
    ----------
    logs: list[dict[str, Any]]
        List of firewall log dictionaries
        
    Returns
    -------
    pd.DataFrame
        DataFrame with timestamp and count columns
    """
    df = pd.DataFrame(logs)
    if 'log_time' not in df.columns:
        return pd.DataFrame(columns=['timestamp', 'count'])
    
    df['timestamp'] = pd.to_datetime(df['log_time'])
    df['date'] = df['timestamp'].dt.date
    activity = df.groupby('date').size().reset_index(name='count')
    activity.columns = ['timestamp', 'count']
    return activity


def aggregate_country_data(logs: list[dict[str, Any]], top_n: int = 10) -> pd.DataFrame:
    """Aggregate firewall logs by country for country graph.
    
    Parameters
    ----------
    logs: list[dict[str, Any]]
        List of firewall log dictionaries with geolocation data
    top_n: int
        Number of top countries to return
        
    Returns
    -------
    pd.DataFrame
        DataFrame with country and count columns
    """
    df = pd.DataFrame(logs)
    if 'country' not in df.columns:
        return pd.DataFrame(columns=['country', 'count'])
    
    countries = df['country'].value_counts().head(top_n).reset_index()
    countries.columns = ['country', 'count']
    return countries


def aggregate_port_data(logs: list[dict[str, Any]], top_n: int = 10) -> pd.DataFrame:
    """Aggregate firewall logs by destination port for port graph.
    
    Parameters
    ----------
    logs: list[dict[str, Any]]
        List of firewall log dictionaries
    top_n: int
        Number of top ports to return
        
    Returns
    -------
    pd.DataFrame
        DataFrame with port and count columns
    """
    df = pd.DataFrame(logs)
    if 'dport' not in df.columns:
        return pd.DataFrame(columns=['port', 'count'])
    
    ports = df['dport'].value_counts().head(top_n).reset_index()
    ports.columns = ['port', 'count']
    return ports


def aggregate_protocol_data(logs: list[dict[str, Any]]) -> pd.DataFrame:
    """Aggregate firewall logs by protocol for protocol graph.
    
    Parameters
    ----------
    logs: list[dict[str, Any]]
        List of firewall log dictionaries
        
    Returns
    -------
    pd.DataFrame
        DataFrame with protocol and count columns
    """
    df = pd.DataFrame(logs)
    if 'protocol' not in df.columns:
        return pd.DataFrame(columns=['protocol', 'count'])
    
    protocols = df['protocol'].value_counts().reset_index()
    protocols.columns = ['protocol', 'count']
    return protocols


def aggregate_action_data(logs: list[dict[str, Any]]) -> pd.DataFrame:
    """Aggregate firewall logs by action for action graph.
    
    Parameters
    ----------
    logs: list[dict[str, Any]]
        List of firewall log dictionaries
        
    Returns
    -------
    pd.DataFrame
        DataFrame with action and count columns
    """
    df = pd.DataFrame(logs)
    if 'action' not in df.columns:
        return pd.DataFrame(columns=['action', 'count'])
    
    actions = df['action'].value_counts().reset_index()
    actions.columns = ['action', 'count']
    return actions


def plot_activity_graph(data: pd.DataFrame, output_path: Path) -> None:
    """Generate time series graph of firewall activity.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame with timestamp and count columns
    output_path: Path
        Path to save the graph
    """
    plt.figure(figsize=(12, 6))
    plt.plot(data['timestamp'], data['count'], marker='o')
    plt.xlabel('Date')
    plt.ylabel('Event Count')
    plt.title('Firewall Activity Over Time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_country_graph(data: pd.DataFrame, output_path: Path) -> None:
    """Generate bar chart of top source countries.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame with country and count columns
    output_path: Path
        Path to save the graph
    """
    plt.figure(figsize=(12, 6))
    plt.bar(data['country'], data['count'])
    plt.xlabel('Country')
    plt.ylabel('Event Count')
    plt.title('Top Source Countries')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_port_graph(data: pd.DataFrame, output_path: Path) -> None:
    """Generate bar chart of most targeted ports.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame with port and count columns
    output_path: Path
        Path to save the graph
    """
    plt.figure(figsize=(12, 6))
    plt.bar(data['port'].astype(str), data['count'])
    plt.xlabel('Port')
    plt.ylabel('Event Count')
    plt.title('Most Targeted Ports')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_protocol_graph(data: pd.DataFrame, output_path: Path) -> None:
    """Generate pie chart of protocol distribution.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame with protocol and count columns
    output_path: Path
        Path to save the graph
    """
    plt.figure(figsize=(10, 8))
    plt.pie(data['count'], labels=data['protocol'], autopct='%1.1f%%')
    plt.title('Protocol Distribution')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_action_graph(data: pd.DataFrame, output_path: Path) -> None:
    """Generate bar chart of action distribution.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame with action and count columns
    output_path: Path
        Path to save the graph
    """
    plt.figure(figsize=(10, 6))
    plt.bar(data['action'], data['count'])
    plt.xlabel('Action')
    plt.ylabel('Event Count')
    plt.title('Firewall Action Distribution')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def export_data_csv(data: pd.DataFrame, output_path: Path) -> None:
    """Export data to CSV file.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame to export
    output_path: Path
        Path to save the CSV file
    """
    data.to_csv(output_path, index=False)


def export_data_json(data: pd.DataFrame, output_path: Path) -> None:
    """Export data to JSON file.
    
    Parameters
    ----------
    data: pd.DataFrame
        DataFrame to export
    output_path: Path
        Path to save the JSON file
    """
    data.to_json(output_path, orient='records', indent=2)
