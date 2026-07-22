# DARK MATER | MCP Kali Server v2.0 Enterprise

<div align="center">
  <img src="https://raw.githubusercontent.com/khalilpreview/M7yapp9sColl3c1oncdn/refs/heads/main/image%20(35).png" alt="DARK MATER MCP Kali Server" width="100%" />
</div>

<div align="center">
  <h3>🔒 Production-Ready Security Testing Platform</h3>
  <p>A powerful, enterprise-grade Model Context Protocol (MCP) server for security testing, network reconnaissance, and vulnerability assessments with Kali Linux tools.</p>
  <p><strong>🏢 Powered by <a href="https://zyniq.solutions">Zyniq Solutions</a></strong></p>
  
  <!-- Technology Stack Badges -->
  <p>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux" />
    <img src="https://img.shields.io/badge/Docker_Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker Compose" />
    <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
    <img src="https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=prometheus&logoColor=white" alt="Prometheus" />
  </p>
  
  <!-- Status Badges -->
  <p>
    <img src="https://img.shields.io/badge/Version-2.0.0-brightgreen?style=flat-square" alt="Version" />
    <img src="https://img.shields.io/badge/OpenMCP-JSON--RPC%202.0-blue?style=flat-square" alt="OpenMCP Standard" />
    <img src="https://img.shields.io/badge/Status-Production%20Ready-success?style=flat-square" alt="Status" />
    <img src="https://img.shields.io/badge/License-Commercial-gold?style=flat-square" alt="License" />
    <img src="https://img.shields.io/badge/Security-Verified%20E2E-orange?style=flat-square" alt="Security" />
  </p>
</div>

---

## 🌟 Key Enterprise Features

- **🌐 Standard OpenMCP JSON-RPC 2.0 (`/mcp`)**: Native protocol support for `initialize`, `tools/list`, and `tools/call` compatible with any standard MCP client or dashboard.
- **🔐 Multi-Tenancy & RBAC Scopes**: Granular client token scoping (`recon:read`, `recon:execute`, `audit:execute`, `admin:all`) and per-tenant CIDR target guardrails.
- **💾 Persistent Async Job Queue (SQLite)**: Asynchronous task tracking backed by a durable SQLite database (`jobs.db`) to ensure long-running scans survive service restarts.
- **📡 Server-Sent Events (SSE) Live Streaming**: Stream real-time stdout/stderr logs and state updates directly to clients via `GET /tools/jobs/{job_id}/stream`.
- **🛡️ Smart Guardrails & Destructive Checks**: CIDR subnet validation (`allowed_cidrs`), automated check-only modes, and strict rate-limiting.
- **📦 SIEM Audit Exporter**: Structured JSON security logging with configurable webhook export (`MCP_SIEM_WEBHOOK_URL`).
- **🐍 Python Client SDK**: Importable SDK (`darkmater_mcp.DarkMaterClient`) for rapid Python & AI agent integration.
- **📊 Prometheus Observability**: Production metric collection at `/metrics` measuring job execution times, queue sizes, and error rates.
- **🤖 Ollama AI Integration**: Built-in integration with local Ollama service (`http://localhost:11434/` with `gemma4:e4b`) for automated vulnerability summarization and tool recommendations.

---

## 🏗️ System Architecture

```
                      +-----------------------------------+
                      |   Client Application / Dashboard   |
                      |   (LangChain / React / Custom)    |
                      +-----------------+-----------------+
                                        |
                   Bearer JWT / OpenMCP | JSON-RPC 2.0 / SSE Stream
                                        v
+-----------------------------------------------------------------------------------+
|                            DARK MATER MCP API SERVER                              |
|                                                                                   |
|  +--------------------+  +---------------------+  +----------------------------+  |
|  | Multi-Tenant Auth  |  | Persistent Job Store|  | OpenMCP Standard Transport |  |
|  | & RBAC Guardrails  |  | (SQLite / Disk WAL) |  | (/mcp Endpoint + SDKs)     |  |
|  +---------+----------+  +----------+----------+  +-------------+--------------+  |
|            |                        |                           |                 |
+------------|------------------------|---------------------------|-----------------+
             |                        |                           |
             +------------------------+---------------------------+
                                      |
                                      v
                 +------------------------------------------+
                 | Ephemeral Container Sidecar Runner Engine|
                 |  (cgroup & network sandboxed executions) |
                 +--------------------+---------------------+
                                      |
                                      v
                 +------------------------------------------+
                 | Benign Target & SIEM Audit Log Exporter  |
                 | (Automated E2E Testbed & Observability)  |
                 +------------------------------------------+
```

---

## 🚀 Quick Start Guide

### Option 1: Docker Compose Deployment (Recommended)

All components are dockerized and managed via `docker-compose.yml`:

```bash
# 1. Clone repository
git clone https://github.com/ZYNIQ-SOLUTIONS/DARK-MATER-Kali-Linux-MCP-Server.git
cd DARK-MATER-Kali-Linux-MCP-Server

# 2. Build and start containers in detached mode
docker-compose up -d --build

# 3. View live server logs
docker-compose logs -f kali-api

# 4. Check container status
docker-compose ps
```

### Option 2: Native Linux Installation (Systemd)

```bash
# 1. Run automated installer (requires root)
curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh | sudo bash

# 2. Start server service
sudo systemctl start mcp-kali-server

# 3. Verify status
sudo systemctl status mcp-kali-server
```

---

## 🔐 Credentials & Enrollment

### Step 1: Locate Enrollment Token
```bash
# Docker Container
docker exec mcp-kali-api cat /etc/mcp-kali/enroll.json

# Native Host
cat /etc/mcp-kali/enroll.json
```

### Step 2: Register & Obtain API Key
```bash
curl -sS -X POST http://localhost:5000/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "id": "kali-docker-test",
    "token": "test_token",
    "label": "Production-Lab-1"
  }'
```

**Response**:
```json
{
  "server_id": "kali-docker-test",
  "api_key": "d90b53b206bdec6ac51a4f7d18a47fc17fd9d25945d48055ebc0bedc8d7980d9",
  "label": "Production-Lab-1"
}
```

Use this `api_key` in the `Authorization: Bearer <api_key>` header for all API requests.

---

## 📖 Complete API Reference

### 1. Server Health Check
```bash
curl -sS -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:5000/health"
```

### 2. OpenMCP JSON-RPC 2.0 Standard (`/mcp`)
```bash
# Initialize Session
curl -sS -X POST "http://localhost:5000/mcp" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1
  }'

# List Available Tools via OpenMCP
curl -sS -X POST "http://localhost:5000/mcp" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 2
  }'

# Execute Tool via OpenMCP
curl -sS -X POST "http://localhost:5000/mcp" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "net.scan_basic",
      "arguments": { "target": "127.0.0.1", "fast": true }
    },
    "id": 3
  }'
```

### 3. Asynchronous Job Execution & SSE Event Streaming

```bash
# 1. Submit an Async Background Job
JOB_ID=$(curl -sS -X POST "http://localhost:5000/tools/jobs" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": { "target": "192.168.65.0/24", "fast": true }
  }' | jq -r '.job_id')

# 2. Poll Job Status
curl -sS -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:5000/tools/jobs/${JOB_ID}"

# 3. Stream Real-Time SSE Updates
curl -N -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:5000/tools/jobs/${JOB_ID}/stream"
```

### 4. Prometheus Metrics Endpoint
```bash
curl -sS "http://localhost:5000/metrics"
```

---

## 🐍 Python Client SDK Usage

The python SDK is located in `sdk/python/darkmater_mcp`.

```python
from darkmater_mcp import DarkMaterClient

# Initialize client
client = DarkMaterClient(base_url="http://localhost:5000", api_key="YOUR_API_KEY")

# 1. Health check
print("Health:", client.health())

# 2. List tools
tools = client.list_tools()
print(f"Tools available: {len(tools)}")

# 3. Synchronous execution
scan_result = client.call_tool("net.scan_basic", {"target": "127.0.0.1", "fast": True})
print("Scan Summary:", scan_result.get("summary"))

# 4. Asynchronous persistent job submission
job_id = client.submit_job("net.scan_basic", {"target": "127.0.0.1", "fast": True})
print(f"Async Job ID: {job_id}")

# 5. OpenMCP Standard JSON-RPC Call
rpc_resp = client.jsonrpc_request("initialize")
print("OpenMCP Init:", rpc_resp.get("result"))
```

---

## ⚙️ Scope Configuration & Security Guardrails

Guardrails are managed via `/etc/mcp-kali/scope.json`:

```json
{
  "allowed_cidrs": [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "127.0.0.1/32"
  ],
  "allow_destructive": false
}
```

- `allowed_cidrs`: Whitelisted networks for scanning and assessment targets.
- `allow_destructive`: When set to `false`, destructive or intrusive exploits are blocked automatically.

---

## 🤖 Ollama AI Analysis Integration

The MCP server connects directly to your exposed Ollama instance for automated AI analysis and tool recommendations:

```bash
# Environment Configuration
export OLLAMA_URL="http://localhost:11434/"
export OLLAMA_MODEL="gemma4:e4b"
```

### AI Job Analysis Endpoint
```bash
curl -sS -X POST -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:5000/tools/jobs/${JOB_ID}/analyze"
```

---

## 🧪 Automated E2E Testing Suite

Run the full end-to-end master test suite to verify server functionality:

```bash
# Run E2E Test Suite locally
python3 tests/e2e/test_master_e2e.py

# Run unit and integration tests
python3 tests/run_tests.py
```

---

## 📄 License & Commercial Support

**DARK MATER MCP Kali Server** is a private, commercial security platform powered by **Zyniq Solutions**.

- **Company**: [Zyniq Solutions](https://zyniq.solutions)
- **Support**: [contact@zyniq.solutions](mailto:contact@zyniq.solutions)
- **License**: Commercial / Private Access
