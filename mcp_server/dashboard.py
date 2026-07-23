"""
Dashboard integration module for DARK MATTER MCP Client.
Provides specialized endpoints and authentication for dashboard connectivity.
"""

import logging
import hashlib
import hmac
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
from pydantic import BaseModel
from fastapi import HTTPException, status
import json

from .util import safe_json_load, safe_json_save

logger = logging.getLogger(__name__)

# Dashboard-specific models
class DashboardAuthRequest(BaseModel):
    """Dashboard authentication request."""
    dashboard_id: str
    api_key: str
    signature: str
    timestamp: int
    
class DashboardConnectionInfo(BaseModel):
    """Dashboard connection information."""
    dashboard_id: str
    server_id: str
    connection_token: str
    expires_at: datetime
    permissions: List[str]
    
class DashboardCapabilities(BaseModel):
    """Dashboard capabilities and feature set."""
    version: str = "2.0.0"
    features: Dict[str, bool]
    endpoints: List[Dict[str, Any]]
    websocket_support: bool = True
    real_time_updates: bool = True

class DashboardManager:
    """Manages dashboard connections and specialized features."""
    
    def __init__(self):
        # Platform-appropriate config directory
        import os
        if os.name == 'nt':  # Windows
            self.config_dir = Path.home() / ".mcp-kali" / "dashboard"
        else:  # Linux/Unix
            self.config_dir = Path("/etc/mcp-kali/dashboard")
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.connections_file = self.config_dir / "connections.json"
        self.dashboard_secret = self._load_or_create_secret()
    
    def _load_or_create_secret(self) -> str:
        """Load or create dashboard secret for signature verification."""
        secret_file = self.config_dir / "dashboard_secret.txt"
        
        if secret_file.exists():
            try:
                with open(secret_file, 'r') as f:
                    return f.read().strip()
            except Exception as e:
                logger.error(f"Error reading dashboard secret: {e}")
        
        # Generate new secret
        import secrets
        secret = secrets.token_hex(32)
        
        try:
            with open(secret_file, 'w') as f:
                f.write(secret)
            secret_file.chmod(0o600)  # Secure permissions
            logger.info("Generated new dashboard secret")
            return secret
        except Exception as e:
            logger.error(f"Error saving dashboard secret: {e}")
            return secret
    
    def verify_dashboard_signature(self, dashboard_id: str, api_key: str, 
                                 timestamp: int, signature: str) -> bool:
        """Verify dashboard request signature."""
        try:
            # Check timestamp (prevent replay attacks)
            current_time = int(time.time())
            if abs(current_time - timestamp) > 300:  # 5 minute window
                logger.warning(f"Dashboard signature timestamp out of range: {dashboard_id}")
                return False
            
            # Create expected signature
            message = f"{dashboard_id}:{api_key}:{timestamp}"
            expected_signature = hmac.new(
                self.dashboard_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Constant-time comparison
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Error verifying dashboard signature: {e}")
            return False
    
    def authenticate_dashboard(self, auth_request: DashboardAuthRequest) -> Optional[DashboardConnectionInfo]:
        """Authenticate dashboard and create connection token."""
        try:
            # Verify signature
            if not self.verify_dashboard_signature(
                auth_request.dashboard_id,
                auth_request.api_key,
                auth_request.timestamp,
                auth_request.signature
            ):
                logger.warning(f"Invalid dashboard signature: {auth_request.dashboard_id}")
                return None
            
            # Verify API key (basic check - you might want to enhance this)
            # For now, we'll accept any valid API key format
            if not auth_request.api_key or len(auth_request.api_key) < 16:
                logger.warning(f"Invalid API key format: {auth_request.dashboard_id}")
                return None
            
            # Generate connection token
            import secrets
            connection_token = secrets.token_urlsafe(32)
            
            # Create connection info
            connection_info = DashboardConnectionInfo(
                dashboard_id=auth_request.dashboard_id,
                server_id=auth_request.api_key[-8:],  # Use last 8 chars as server ID
                connection_token=connection_token,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                permissions=[
                    "tools:read",
                    "tools:execute", 
                    "artifacts:read",
                    "memory:read",
                    "metrics:read",
                    "audit:read",
                    "health:read"
                ]
            )
            
            # Store connection
            self._store_connection(connection_info)
            
            logger.info(f"Dashboard authenticated: {auth_request.dashboard_id}")
            return connection_info
            
        except Exception as e:
            logger.error(f"Error authenticating dashboard: {e}")
            return None
    
    def _store_connection(self, connection_info: DashboardConnectionInfo):
        """Store dashboard connection information."""
        try:
            # Load existing connections
            connections = {}
            if self.connections_file.exists():
                connections = safe_json_load(self.connections_file) or {}
            
            # Add new connection
            connections[connection_info.dashboard_id] = {
                "server_id": connection_info.server_id,
                "connection_token": connection_info.connection_token,
                "expires_at": connection_info.expires_at.isoformat(),
                "permissions": connection_info.permissions,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Save connections
            safe_json_save(self.connections_file, connections)
            
        except Exception as e:
            logger.error(f"Error storing dashboard connection: {e}")
    
    def verify_connection_token(self, dashboard_id: str, connection_token: str) -> bool:
        """Verify dashboard connection token."""
        try:
            if not self.connections_file.exists():
                return False
            
            connections = safe_json_load(self.connections_file) or {}
            connection = connections.get(dashboard_id)
            
            if not connection:
                return False
            
            # Check token
            if connection.get("connection_token") != connection_token:
                return False
            
            # Check expiration
            expires_at = datetime.fromisoformat(connection.get("expires_at", ""))
            if datetime.now(timezone.utc) > expires_at:
                logger.info(f"Dashboard connection expired: {dashboard_id}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying connection token: {e}")
            return False
    
    def get_dashboard_capabilities(self) -> DashboardCapabilities:
        """Get capabilities available to dashboard."""
        return DashboardCapabilities(
            version="2.0.0",
            features={
                "real_time_scanning": True,
                "artifact_storage": True,
                "memory_hooks": True,
                "audit_logging": True,
                "metrics_collection": True,
                "rate_limiting": True,
                "scope_validation": True,
                "ngrok_integration": True,
                "batch_operations": True,
                "webhook_notifications": True,
                "report_generation": True,
                "third_party_integrations": True
            },
            endpoints=[
                {"path": "/health", "methods": ["GET"], "description": "Basic health check"},
                {"path": "/health/detailed", "methods": ["GET"], "description": "Detailed health with metrics"},
                {"path": "/tools/list", "methods": ["GET"], "description": "List available tools"},
                {"path": "/tools/call", "methods": ["POST"], "description": "Execute security tools"},
                {"path": "/artifacts/list", "methods": ["GET"], "description": "List stored artifacts"},
                {"path": "/artifacts/read", "methods": ["GET"], "description": "Read artifact content"},
                {"path": "/memory/search", "methods": ["GET"], "description": "Search observations"},
                {"path": "/memory/stats", "methods": ["GET"], "description": "Memory statistics"},
                {"path": "/api/v2/metrics", "methods": ["GET"], "description": "Server metrics"},
                {"path": "/api/v2/audit/events", "methods": ["GET"], "description": "Audit events"},
                {"path": "/api/v2/audit/stats", "methods": ["GET"], "description": "Audit statistics"},
                {"path": "/ngrok/info", "methods": ["GET"], "description": "Ngrok tunnel info"},
                {"path": "/ngrok/metrics", "methods": ["GET"], "description": "Ngrok metrics"}
            ],
            websocket_support=True,
            real_time_updates=True
        )
    
    def get_dashboard_specific_data(self, dashboard_id: str) -> Dict[str, Any]:
        """Get dashboard-specific aggregated data."""
        try:
            from .metrics import metrics_collector
            from .tools import list_tools
            from .memory import get_observation_stats
            
            # Get comprehensive data for dashboard
            tools_list = list_tools()
            metrics = metrics_collector.get_all_metrics()
            
            # Get recent activity summary
            recent_activity = {
                "total_requests_today": metrics.get("requests", {}).get("total_requests", 0),
                "total_tool_executions": metrics.get("tools", {}).get("total_tool_executions", 0),
                "error_rate": metrics.get("requests", {}).get("error_rate", 0),
                "uptime_hours": metrics.get("uptime_seconds", 0) / 3600,
                "system_health": {
                    "cpu_percent": metrics.get("system", {}).get("current", {}).get("cpu_percent", 0),
                    "memory_percent": metrics.get("system", {}).get("current", {}).get("memory_percent", 0)
                }
            }
            
            return {
                "dashboard_id": dashboard_id,
                "server_time": datetime.now(timezone.utc).isoformat(),
                "available_tools": len(tools_list),
                "tool_categories": list(set(tool.get("category", "general") for tool in tools_list)),
                "recent_activity": recent_activity,
                "capabilities": self.get_dashboard_capabilities().model_dump(),
                "connection_status": "active"
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {"error": str(e)}

# Global dashboard manager instance
dashboard_manager = DashboardManager()

async def verify_dashboard_auth(dashboard_id: str, connection_token: str) -> bool:
    """Verify dashboard authentication for endpoints."""
    return dashboard_manager.verify_connection_token(dashboard_id, connection_token)