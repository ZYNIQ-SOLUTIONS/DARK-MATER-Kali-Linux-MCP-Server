"""
OpenMCP Standard Protocol (JSON-RPC 2.0) Module for MCP Kali Server.
Supports standard MCP client integration (/mcp endpoint).
"""

import json
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel

from .tools import tool_registry, call_tool
from .scope import validate_scope_and_destructiveness

logger = logging.getLogger(__name__)

SERVER_INFO = {
    "name": "dark-mater-kali-mcp-server",
    "version": "2.0.0"
}

PROTOCOL_VERSION = "2024-11-05"

def handle_jsonrpc_request(server_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process incoming JSON-RPC 2.0 OpenMCP request."""
    method = request_data.get("method")
    req_id = request_data.get("id")
    params = request_data.get("params", {}) or {}

    logger.info(f"Processing OpenMCP method: {method}")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "prompts": {},
                    "resources": {}
                },
                "serverInfo": SERVER_INFO
            }
        }

    elif method == "tools/list":
        tools_list = tool_registry.list_tools()
        mcp_tools = []
        for t in tools_list:
            mcp_tools.append({
                "name": t.get("name"),
                "description": t.get("description", ""),
                "inputSchema": t.get("schema", {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP/Subnet"}
                    },
                    "required": ["target"]
                })
            })
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": mcp_tools
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Missing 'name' in arguments"}
            }

        res = call_tool(server_id, tool_name, arguments)
        res_dict = res.to_dict()

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res_dict, indent=2)
                    }
                ],
                "isError": res_dict.get("rc") != 0
            }
        }

    elif method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }
