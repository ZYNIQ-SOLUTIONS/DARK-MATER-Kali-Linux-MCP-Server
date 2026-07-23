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

    def stream_job(self, job_id: str):
        """Stream a tool execution job via Server-Sent Events (SSE). Yields parsed JSON chunks."""
        req = urllib.request.Request(f"{self.base_url}/tools/jobs/{job_id}/stream", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            for line in resp:
                decoded_line = line.decode('utf-8').strip()
                if decoded_line.startswith('data: '):
                    yield json.loads(decoded_line[6:])

    def list_artifacts(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """List generated artifacts."""
        req = urllib.request.Request(f"{self.base_url}/artifacts/list?limit={limit}&offset={offset}", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def read_artifact(self, artifact_uri: str) -> Dict[str, Any]:
        """Read artifact content."""
        from urllib.parse import quote
        req = urllib.request.Request(f"{self.base_url}/artifacts/read?uri={quote(artifact_uri)}", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def search_memory(self, query: str = "", limit: int = 10) -> Dict[str, Any]:
        """Search tool execution memory."""
        from urllib.parse import quote
        url = f"{self.base_url}/memory/search?limit={limit}"
        if query:
            url += f"&query={quote(query)}"
        req = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def memory_stats(self) -> Dict[str, Any]:
        """Get memory database statistics."""
        req = urllib.request.Request(f"{self.base_url}/memory/stats", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def memory_append(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Append to memory database directly."""
        payload = json.dumps(content).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/memory/append", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def dashboard_capabilities(self) -> Dict[str, Any]:
        """Get dashboard capabilities."""
        req = urllib.request.Request(f"{self.base_url}/api/v2/dashboard/capabilities", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def generate_report(self, config: Dict[str, Any], scan_ids: List[str] = None) -> Dict[str, Any]:
        """Generate a security report."""
        payload_data = {"config": config}
        if scan_ids:
            payload_data["scan_ids"] = scan_ids
        payload = json.dumps(payload_data).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/v2/reports/generate", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def list_webhooks(self) -> Dict[str, Any]:
        """List configured webhooks."""
        req = urllib.request.Request(f"{self.base_url}/api/v2/webhooks", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def add_webhook(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new webhook configuration."""
        payload = json.dumps(webhook_data).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/v2/webhooks", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def audit_events(self, limit: int = 100) -> Dict[str, Any]:
        """Get audit log events."""
        req = urllib.request.Request(f"{self.base_url}/api/v2/audit/events?limit={limit}", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def audit_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        req = urllib.request.Request(f"{self.base_url}/api/v2/audit/stats", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def metrics(self) -> Dict[str, Any]:
        """Get Prometheus formatted metrics or JSON metrics."""
        req = urllib.request.Request(f"{self.base_url}/metrics", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            content_type = resp.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                return json.loads(resp.read().decode("utf-8"))
            return {"raw_metrics": resp.read().decode("utf-8")}

    def config_scope(self) -> Dict[str, Any]:
        """Get current scope configuration."""
        req = urllib.request.Request(f"{self.base_url}/config/scope", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def ngrok_info(self) -> Dict[str, Any]:
        """Get Ngrok tunnel information."""
        req = urllib.request.Request(f"{self.base_url}/ngrok/info", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def auth_token(self, auth_req: Dict[str, Any]) -> Dict[str, Any]:
        """Request authentication token (Dashboard Auth)."""
        payload = json.dumps(auth_req).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/auth/token", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def enroll(self, enrollment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll the server or register client."""
        payload = json.dumps(enrollment_data).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/enroll", data=payload, headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration."""
        req = urllib.request.Request(f"{self.base_url}/llm/config", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def llm_context(self) -> Dict[str, Any]:
        """Get system context and prompt for LLM."""
        req = urllib.request.Request(f"{self.base_url}/llm/context", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def llm_knowledge_docs(self) -> Dict[str, Any]:
        """Get knowledgebase documents for LLM injection."""
        req = urllib.request.Request(f"{self.base_url}/llm/knowledge/docs", headers=self._headers())
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
