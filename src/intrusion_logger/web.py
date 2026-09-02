"""Web API module for intrusion_logger dashboard.

This module provides a FastAPI-based web server for real-time
visualization of firewall logs and geolocation data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from .config import load_config
from .database import Database
from .graphing import (
    aggregate_activity_data,
    aggregate_country_data,
    aggregate_port_data,
    aggregate_protocol_data,
    aggregate_action_data,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="Intrusion Logger Dashboard", version="0.1.9")

# Global state for WebSocket connections
active_connections: list[WebSocket] = []


@app.get("/")
async def root(request: Any) -> HTMLResponse:
    """Serve the main dashboard page."""
    # Get the host from the request for WebSocket connection
    host = request.headers.get("host", "localhost:8000")
    ws_protocol = "wss" if "https" in request.url.scheme else "ws"
    ws_url = f"{ws_protocol}://{host}/ws"
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intrusion Logger Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
            .card {{ background: #16213e; padding: 20px; border-radius: 10px; }}
            .card h2 {{ margin-top: 0; color: #0f3460; }}
            .stats {{ display: flex; justify-content: space-around; margin-bottom: 20px; }}
            .stat {{ text-align: center; }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #e94560; }}
            .stat-label {{ font-size: 0.9em; color: #888; }}
            canvas {{ max-height: 300px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Intrusion Logger Dashboard</h1>
                <p>Real-time firewall log monitoring</p>
            </div>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="total-logs">-</div>
                    <div class="stat-label">Total Logs</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="blocked-logs">-</div>
                    <div class="stat-label">Blocked</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="unique-ips">-</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
            </div>
            <div class="grid">
                <div class="card">
                    <h2>Activity Over Time</h2>
                    <canvas id="activityChart"></canvas>
                </div>
                <div class="card">
                    <h2>Top Countries</h2>
                    <canvas id="countryChart"></canvas>
                </div>
                <div class="card">
                    <h2>Top Ports</h2>
                    <canvas id="portChart"></canvas>
                </div>
                <div class="card">
                    <h2>Action Distribution</h2>
                    <canvas id="actionChart"></canvas>
                </div>
            </div>
        </div>
        <script>
            const activityChart = new Chart(document.getElementById('activityChart'), {{
                type: 'line',
                data: {{ labels: [], datasets: [{{ label: 'Events', data: [], borderColor: '#e94560', tension: 0.1 }}] }},
                options: {{ responsive: true, scales: {{ y: {{ beginAtZero: true }} }} }}
            }});
            const countryChart = new Chart(document.getElementById('countryChart'), {{
                type: 'bar',
                data: {{ labels: [], datasets: [{{ label: 'Count', data: [], backgroundColor: '#0f3460' }}] }},
                options: {{ responsive: true, indexAxis: 'y' }}
            }});
            const portChart = new Chart(document.getElementById('portChart'), {{
                type: 'bar',
                data: {{ labels: [], datasets: [{{ label: 'Count', data: [], backgroundColor: '#533483' }}] }},
                options: {{ responsive: true }}
            }});
            const actionChart = new Chart(document.getElementById('actionChart'), {{
                type: 'doughnut',
                data: {{ labels: [], datasets: [{{ data: [], backgroundColor: ['#e94560', '#0f3460', '#533483', '#16213e'] }}] }},
                options: {{ responsive: true }}
            }});

            const ws = new WebSocket('{ws_url}');
            ws.onmessage = (event) => {{
                const data = JSON.parse(event.data);
                if (data.type === 'stats') {{
                    document.getElementById('total-logs').textContent = data.total_logs;
                    document.getElementById('blocked-logs').textContent = data.blocked_logs;
                    document.getElementById('unique-ips').textContent = data.unique_ips;
                }} else if (data.type === 'activity') {{
                    activityChart.data.labels = data.labels;
                    activityChart.data.datasets[0].data = data.values;
                    activityChart.update();
                }} else if (data.type === 'countries') {{
                    countryChart.data.labels = data.labels;
                    countryChart.data.datasets[0].data = data.values;
                    countryChart.update();
                }} else if (data.type === 'ports') {{
                    portChart.data.labels = data.labels;
                    portChart.data.datasets[0].data = data.values;
                    portChart.update();
                }} else if (data.type === 'actions') {{
                    actionChart.data.labels = data.labels;
                    actionChart.data.datasets[0].data = data.values;
                    actionChart.update();
                }}
            }};
        </script>
    </body>
    </html>
    """)


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Get current database statistics."""
    config = load_config()
    db = Database(config.database)
    
    table = f"{config.collector.schema}.{config.collector.table}"
    
    try:
        db.connect()
        
        # Total logs
        total_sql = f"SELECT COUNT(*) as count FROM {table}"
        total_result = db.fetch_one(total_sql)
        total_logs = total_result['count'] if total_result else 0
        
        # Blocked logs (REJECT/DENY)
        blocked_sql = f"SELECT COUNT(*) as count FROM {table} WHERE action IN ('REJECT', 'DENY')"
        blocked_result = db.fetch_one(blocked_sql)
        blocked_logs = blocked_result['count'] if blocked_result else 0
        
        # Unique IPs
        unique_sql = f"SELECT COUNT(DISTINCT src_ip) as count FROM {table}"
        unique_result = db.fetch_one(unique_sql)
        unique_ips = unique_result['count'] if unique_result else 0
        
        db.close()
        
        return {
            "total_logs": total_logs,
            "blocked_logs": blocked_logs,
            "unique_ips": unique_ips,
        }
    except Exception as exc:
        logger.error(f"Failed to get stats: {exc}")
        db.close()
        raise


@app.get("/api/activity")
async def get_activity(hours: int = 24) -> dict[str, Any]:
    """Get activity data for the specified time period."""
    config = load_config()
    db = Database(config.database)
    
    table = f"{config.collector.schema}.{config.collector.table}"
    
    try:
        db.connect()
        
        sql = f"""
            SELECT log_time, action, src_ip, dst_ip, dport
            FROM {table}
            WHERE log_time > NOW() - INTERVAL '{hours} hours'
            ORDER BY log_time ASC
        """
        results = db.fetch_all(sql)
        
        db.close()
        
        # Convert to format expected by aggregation function
        logs_list = []
        for row in results:
            logs_list.append({
                'log_time': row['log_time'],
                'action': row['action'],
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'dport': row['dport'],
            })
        
        activity_data = aggregate_activity_data(logs_list)
        
        return {
            "labels": [item['timestamp'] for item in activity_data],
            "values": [item['count'] for item in activity_data],
        }
    except Exception as exc:
        logger.error(f"Failed to get activity data: {exc}")
        db.close()
        raise


@app.get("/api/countries")
async def get_countries(top_n: int = 10) -> dict[str, Any]:
    """Get top countries by source IP count."""
    config = load_config()
    db = Database(config.database)
    
    table = f"{config.collector.schema}.{config.collector.table}"
    
    try:
        db.connect()
        
        # Get recent logs with geolocation
        sql = f"""
            SELECT src_ip, COUNT(*) as count
            FROM {table}
            WHERE log_time > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 100
        """
        results = db.fetch_all(sql)
        
        db.close()
        
        # For now, just return IP counts (geolocation would need to be added)
        return {
            "labels": [row['src_ip'] for row in results[:top_n]],
            "values": [row['count'] for row in results[:top_n]],
        }
    except Exception as exc:
        logger.error(f"Failed to get country data: {exc}")
        db.close()
        raise


@app.get("/api/ports")
async def get_ports(top_n: int = 10) -> dict[str, Any]:
    """Get top destination ports."""
    config = load_config()
    db = Database(config.database)
    
    table = f"{config.collector.schema}.{config.collector.table}"
    
    try:
        db.connect()
        
        sql = f"""
            SELECT dport, COUNT(*) as count
            FROM {table}
            WHERE dport IS NOT NULL AND log_time > NOW() - INTERVAL '24 hours'
            GROUP BY dport
            ORDER BY count DESC
            LIMIT {top_n}
        """
        results = db.fetch_all(sql)
        
        db.close()
        
        return {
            "labels": [str(row['dport']) for row in results],
            "values": [row['count'] for row in results],
        }
    except Exception as exc:
        logger.error(f"Failed to get port data: {exc}")
        db.close()
        raise


@app.get("/api/actions")
async def get_actions() -> dict[str, Any]:
    """Get action distribution."""
    config = load_config()
    db = Database(config.database)
    
    table = f"{config.collector.schema}.{config.collector.table}"
    
    try:
        db.connect()
        
        sql = f"""
            SELECT action, COUNT(*) as count
            FROM {table}
            WHERE log_time > NOW() - INTERVAL '24 hours'
            GROUP BY action
            ORDER BY count DESC
        """
        results = db.fetch_all(sql)
        
        db.close()
        
        return {
            "labels": [row['action'] for row in results],
            "values": [row['count'] for row in results],
        }
    except Exception as exc:
        logger.error(f"Failed to get action data: {exc}")
        db.close()
        raise


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Send stats update
            stats = await get_stats()
            await websocket.send_json({"type": "stats", **stats})
            
            # Send activity update
            activity = await get_activity()
            await websocket.send_json({"type": "activity", **activity})
            
            # Send countries update
            countries = await get_countries()
            await websocket.send_json({"type": "countries", **countries})
            
            # Send ports update
            ports = await get_ports()
            await websocket.send_json({"type": "ports", **ports})
            
            # Send actions update
            actions = await get_actions()
            await websocket.send_json({"type": "actions", **actions})
            
            # Wait before next update (5 seconds)
            import asyncio
            await asyncio.sleep(5)
            
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as exc:
        logger.error(f"WebSocket error: {exc}")
        active_connections.remove(websocket)
