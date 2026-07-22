"""
SIEM & Audit Exporter module for DARK MATER MCP Server.
Exports structured security events to Syslog or external webhook endpoints.
"""

import json
import logging
import urllib.request
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SIEM_WEBHOOK_URL = os.environ.get("MCP_SIEM_WEBHOOK_URL")

class SIEMExporter:
    """SIEM Audit Event Exporter."""
    
    @classmethod
    def emit_event(cls, event_type: str, server_id: str, details: Dict[str, Any]):
        """Emit a structured SIEM audit event."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_id": server_id,
            "event_type": event_type,
            "details": details
        }
        
        # Log to Python logger for systemd / container stdout
        logger.info(f"SIEM_EVENT: {json.dumps(payload)}")
        
        # If webhook configured, send HTTP POST
        if SIEM_WEBHOOK_URL:
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    SIEM_WEBHOOK_URL,
                    data=data,
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    pass
            except Exception as e:
                logger.warning(f"Failed to post event to SIEM webhook: {e}")

siem_exporter = SIEMExporter()
