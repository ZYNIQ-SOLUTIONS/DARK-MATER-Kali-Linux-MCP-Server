"""
Metrics collection module for MCP Kali Server.
Provides comprehensive operational visibility and monitoring.
"""

import time
import psutil
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pydantic import BaseModel
from pathlib import Path

logger = logging.getLogger(__name__)

class MetricsConfig(BaseModel):
    """Metrics collection configuration."""
    enabled: bool = True
    collection_interval: int = 60  # seconds
    retention_hours: int = 24
    include_system_metrics: bool = True

class MetricsCollector:
    """Comprehensive metrics collection system."""
    
    def __init__(self, config: MetricsConfig = None):
        self.config = config or MetricsConfig()
        self.start_time = time.time()
        
        # Metrics storage (in-memory with time-based retention)
        self._request_counts = defaultdict(int)
        self._response_times = defaultdict(deque)
        self._tool_executions = defaultdict(int)
        self._tool_durations = defaultdict(deque)
        self._error_counts = defaultdict(int)
        self._active_connections = 0
        self._system_metrics_history = deque()
        
        # Last cleanup time
        self._last_cleanup = time.time()
    
    def increment_request_count(self, endpoint: str, method: str, status_code: int):
        """Increment request counter."""
        if not self.config.enabled:
            return
            
        key = f"{method}_{endpoint}_{status_code}"
        self._request_counts[key] += 1
        
        # Track errors separately
        if status_code >= 400:
            error_key = f"{method}_{endpoint}_error"
            self._error_counts[error_key] += 1
    
    def record_response_time(self, endpoint: str, method: str, duration: float):
        """Record response time."""
        if not self.config.enabled:
            return
            
        key = f"{method}_{endpoint}"
        self._response_times[key].append((time.time(), duration))
        
        # Keep only recent entries
        self._cleanup_time_series(self._response_times[key])
    
    def record_tool_execution(self, tool_name: str, success: bool, duration: float):
        """Record tool execution metrics."""
        if not self.config.enabled:
            return
            
        # Count executions
        status = "success" if success else "failure"
        key = f"{tool_name}_{status}"
        self._tool_executions[key] += 1
        
        # Record duration for successful executions
        if success:
            self._tool_durations[tool_name].append((time.time(), duration))
            self._cleanup_time_series(self._tool_durations[tool_name])
    
    def set_active_connections(self, count: int):
        """Set current active connection count."""
        if self.config.enabled:
            self._active_connections = count
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        if not self.config.enabled or not self.config.include_system_metrics:
            return {}
            
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network stats (if available)
            try:
                network = psutil.net_io_counters()
                network_stats = {
                    "bytes_sent": network.bytes_sent,
                    "bytes_received": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_received": network.packets_recv
                }
            except:
                network_stats = {}
            
            metrics = {
                "timestamp": time.time(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": memory.available / (1024 * 1024),
                "memory_used_mb": memory.used / (1024 * 1024),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 * 1024 * 1024),
                "disk_used_gb": disk.used / (1024 * 1024 * 1024),
                **network_stats
            }
            
            # Store in history
            self._system_metrics_history.append(metrics)
            self._cleanup_time_series(self._system_metrics_history)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {"error": str(e)}
    
    def _cleanup_time_series(self, series: deque, max_age_hours: int = None):
        """Remove old entries from time series data."""
        if not series:
            return
            
        max_age = max_age_hours or self.config.retention_hours
        cutoff = time.time() - (max_age * 3600)
        
        # Remove old entries (assuming first element is timestamp)
        while series and series[0][0] < cutoff:
            series.popleft()
    
    def get_request_metrics(self) -> Dict[str, Any]:
        """Get request-related metrics."""
        if not self.config.enabled:
            return {"enabled": False}
            
        # Calculate request rates
        total_requests = sum(self._request_counts.values())
        uptime_hours = (time.time() - self.start_time) / 3600
        
        # Error rates
        total_errors = sum(self._error_counts.values())
        error_rate = total_errors / total_requests if total_requests > 0 else 0
        
        # Response time statistics
        response_time_stats = {}
        for endpoint, times in self._response_times.items():
            if times:
                durations = [t[1] for t in times]
                response_time_stats[endpoint] = {
                    "avg_ms": sum(durations) / len(durations) * 1000,
                    "min_ms": min(durations) * 1000,
                    "max_ms": max(durations) * 1000,
                    "count": len(durations)
                }
        
        return {
            "total_requests": total_requests,
            "requests_per_hour": total_requests / uptime_hours if uptime_hours > 0 else 0,
            "total_errors": total_errors,
            "error_rate": error_rate,
            "active_connections": self._active_connections,
            "uptime_hours": uptime_hours,
            "response_times": response_time_stats,
            "request_counts": dict(self._request_counts),
            "error_counts": dict(self._error_counts)
        }
    
    def get_tool_metrics(self) -> Dict[str, Any]:
        """Get tool execution metrics."""
        if not self.config.enabled:
            return {"enabled": False}
            
        # Tool execution statistics
        tool_stats = {}
        all_tools = set()
        
        # Collect all tool names
        for key in self._tool_executions.keys():
            tool_name = key.rsplit('_', 1)[0]  # Remove _success/_failure suffix
            all_tools.add(tool_name)
        
        # Calculate stats per tool
        for tool_name in all_tools:
            success_count = self._tool_executions.get(f"{tool_name}_success", 0)
            failure_count = self._tool_executions.get(f"{tool_name}_failure", 0)
            total_count = success_count + failure_count
            
            # Duration statistics
            durations = self._tool_durations.get(tool_name, deque())
            duration_stats = {}
            if durations:
                duration_values = [d[1] for d in durations]
                duration_stats = {
                    "avg_seconds": sum(duration_values) / len(duration_values),
                    "min_seconds": min(duration_values),
                    "max_seconds": max(duration_values)
                }
            
            tool_stats[tool_name] = {
                "total_executions": total_count,
                "successful_executions": success_count,
                "failed_executions": failure_count,
                "success_rate": success_count / total_count if total_count > 0 else 0,
                "duration_stats": duration_stats
            }
        
        return {
            "tools": tool_stats,
            "total_tool_executions": sum(self._tool_executions.values())
        }
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current and historical system metrics."""
        if not self.config.enabled or not self.config.include_system_metrics:
            return {"enabled": False}
            
        current = self.collect_system_metrics()
        
        # Calculate trends if we have history
        history_stats = {}
        if len(self._system_metrics_history) > 1:
            # Get metrics from 1 hour ago for trend calculation
            hour_ago = time.time() - 3600
            historical_point = None
            
            for metrics in self._system_metrics_history:
                if metrics["timestamp"] >= hour_ago:
                    historical_point = metrics
                    break
            
            if historical_point:
                history_stats = {
                    "cpu_trend": current.get("cpu_percent", 0) - historical_point.get("cpu_percent", 0),
                    "memory_trend": current.get("memory_percent", 0) - historical_point.get("memory_percent", 0)
                }
        
        return {
            "current": current,
            "trends": history_stats,
            "history_points": len(self._system_metrics_history)
        }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return {
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": time.time() - self.start_time,
            "requests": self.get_request_metrics(),
            "tools": self.get_tool_metrics(),
            "system": self.get_system_metrics(),
            "config": self.config.model_dump()
        }
        
    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus exposition format."""
        lines = []
        
        # 1. Request metrics
        lines.append("# HELP mcp_requests_total Total number of API requests")
        lines.append("# TYPE mcp_requests_total counter")
        for key, count in self._request_counts.items():
            parts = key.split('_', 2)
            if len(parts) >= 3:
                method, endpoint, status = parts[0], parts[1], parts[2]
                lines.append(f'mcp_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {count}')
                
        lines.append("# HELP mcp_errors_total Total number of API errors")
        lines.append("# TYPE mcp_errors_total counter")
        for key, count in self._error_counts.items():
            parts = key.split('_', 2)
            if len(parts) >= 2:
                method, endpoint = parts[0], parts[1]
                lines.append(f'mcp_errors_total{{method="{method}",endpoint="{endpoint}"}} {count}')

        # 2. Tool metrics
        lines.append("# HELP mcp_tool_executions_total Total number of tool executions")
        lines.append("# TYPE mcp_tool_executions_total counter")
        for key, count in self._tool_executions.items():
            parts = key.rsplit('_', 1)
            if len(parts) == 2:
                tool_name, status = parts[0], parts[1]
                lines.append(f'mcp_tool_executions_total{{tool="{tool_name}",status="{status}"}} {count}')
                
        # Tool durations
        lines.append("# HELP mcp_tool_duration_seconds Tool execution duration in seconds")
        lines.append("# TYPE mcp_tool_duration_seconds gauge")
        for tool_name, durations in self._tool_durations.items():
            if durations:
                duration_values = [d[1] for d in durations]
                avg = sum(duration_values) / len(duration_values)
                lines.append(f'mcp_tool_duration_seconds{{tool="{tool_name}"}} {avg}')

        # 3. System metrics
        if self.config.include_system_metrics:
            sys_metrics = self.collect_system_metrics()
            if "error" not in sys_metrics and sys_metrics:
                lines.append("# HELP mcp_system_cpu_percent System CPU utilization")
                lines.append("# TYPE mcp_system_cpu_percent gauge")
                lines.append(f'mcp_system_cpu_percent {sys_metrics.get("cpu_percent", 0.0)}')
                
                lines.append("# HELP mcp_system_memory_percent System Memory utilization")
                lines.append("# TYPE mcp_system_memory_percent gauge")
                lines.append(f'mcp_system_memory_percent {sys_metrics.get("memory_percent", 0.0)}')
                
                lines.append("# HELP mcp_system_memory_used_mb System Memory used (MB)")
                lines.append("# TYPE mcp_system_memory_used_mb gauge")
                lines.append(f'mcp_system_memory_used_mb {sys_metrics.get("memory_used_mb", 0.0)}')
                
        # 4. Server info
        lines.append("# HELP mcp_server_uptime_seconds Server uptime in seconds")
        lines.append("# TYPE mcp_server_uptime_seconds gauge")
        lines.append(f'mcp_server_uptime_seconds {time.time() - self.start_time}')
        
        lines.append("# HELP mcp_active_connections Current active WebSocket/HTTP connections")
        lines.append("# TYPE mcp_active_connections gauge")
        lines.append(f'mcp_active_connections {self._active_connections}')

        # Ensure newline at EOF
        return chr(10).join(lines) + chr(10)
    
    def cleanup_old_data(self):
        """Clean up old metrics data."""
        current_time = time.time()
        
        # Only cleanup every 10 minutes to avoid overhead
        if current_time - self._last_cleanup < 600:
            return
            
        logger.info("Cleaning up old metrics data")
        
        # Clean response times
        for series in self._response_times.values():
            self._cleanup_time_series(series)
        
        # Clean tool durations
        for series in self._tool_durations.values():
            self._cleanup_time_series(series)
        
        # Clean system metrics
        self._cleanup_time_series(self._system_metrics_history)
        
        self._last_cleanup = current_time
        logger.debug("Metrics cleanup completed")

# Global metrics collector instance
metrics_collector = MetricsCollector()

def get_health_metrics() -> Dict[str, Any]:
    """Get health check metrics for monitoring."""
    return {
        "status": "healthy",
        "uptime_seconds": time.time() - metrics_collector.start_time,
        "metrics_enabled": metrics_collector.config.enabled,
        "last_collection": datetime.now().isoformat()
    }
