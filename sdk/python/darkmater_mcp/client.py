"""
DARK MATER MCP Kali Client SDK for Python.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

class DarkMaterClient:
    """Client for interacting with DARK MATER MCP Kali Server."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

    def health(self) -> Dict[str, Any]:
        """Perform health check."""
        req = urllib.request.Request(f"{self.base_url}/health", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def list_tools(self) -> List[Dict[str, Any]]:
        """List available MCP tools."""
        req = urllib.request.Request(f"{self.base_url}/tools/list", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool synchronously."""
        payload = json.dumps({"name": name, "arguments": arguments}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/tools/call", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def submit_job(self, name: str, arguments: Dict[str, Any]) -> str:
        """Submit a tool execution asynchronously and return job_id."""
        payload = json.dumps({"name": name, "arguments": arguments}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/tools/jobs", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("job_id")

    def get_job(self, job_id: str) -> Dict[str, Any]:
        """Get job status and results."""
        req = urllib.request.Request(f"{self.base_url}/tools/jobs/{job_id}", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def jsonrpc_request(self, method: str, params: Optional[Dict[str, Any]] = None, req_id: int = 1) -> Dict[str, Any]:
        """Send standard OpenMCP JSON-RPC request to /mcp."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": req_id
        }).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/mcp", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
