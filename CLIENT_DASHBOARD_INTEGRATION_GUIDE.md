# DARK MATER MCP Server: Client Dashboard Integration Guide

This document is the official integration guide for the **Frontend/Client Dashboard Project**. It outlines the complete lifecycle for interacting with the DARK MATER MCP Kali Server, including authenticating, fetching available tools, submitting asynchronous execution jobs, and streaming live terminal output via Server-Sent Events (SSE).

---

## 1. Authentication & Enrollment

Every API request requires a Bearer token. To get this token, your client must "enroll" with the server using a pre-shared master token.

### Enrollment Request
Send a POST request to the `/enroll` endpoint.

```javascript
// Example: React/Next.js Client Enrollment
async function enrollClient() {
  const response = await fetch('http://localhost:5000/enroll', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: "dashboard-client-01",
      token: "test_token",  // The pre-shared master token from enroll.json
      label: "Main Security Dashboard"
    })
  });

  const data = await response.json();
  if (response.ok) {
    // Store this api_key securely (e.g., in localStorage or an HttpOnly cookie)
    localStorage.setItem('mcp_api_key', data.api_key);
    return data.api_key;
  }
  throw new Error("Enrollment failed: " + data.detail);
}
```

> [!WARNING]  
> The `api_key` must be included in the `Authorization: Bearer <api_key>` header for **all** subsequent requests to the server.

---

## 2. Using the OpenMCP JSON-RPC Interface

The DARK MATER backend natively supports the standard Model Context Protocol (MCP) JSON-RPC 2.0 interface via the `/mcp` endpoint.

### Listing Available Tools
```javascript
async function listTools(apiKey) {
  const response = await fetch('http://localhost:5000/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/list",
      id: 1
    })
  });
  
  const data = await response.json();
  return data.result.tools; // Array of tools and their JSONSchema schemas
}
```

> [!TIP]
> Use `tools/list` to dynamically render forms in your UI based on the `inputSchema` provided by the server for each tool!

---

## 3. Submitting Asynchronous Jobs

Because security scans (like Nmap or Metasploit) take a long time to run, they must be executed asynchronously.

```javascript
async function startScan(apiKey, targetIp) {
  const response = await fetch('http://localhost:5000/tools/jobs', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      name: "recon.nmap_scan",
      arguments: { target: targetIp, fast: true }
    })
  });
  
  const data = await response.json();
  return data.job_id; // e.g., "job_xyz123"
}
```

---

## 4. Live Streaming Terminal Output (SSE)

Once a job is submitted, the dashboard should connect to the Server-Sent Events (SSE) stream to display real-time terminal output to the user.

```javascript
import { useEffect, useState } from 'react';

function LiveTerminal({ jobId, apiKey }) {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('running');

  useEffect(() => {
    if (!jobId) return;

    // Use EventSource for SSE. Note: Native EventSource doesn't support custom headers easily.
    // For React apps, we recommend using '@microsoft/fetch-event-source' to pass Bearer tokens.
    import { fetchEventSource } from '@microsoft/fetch-event-source';
    
    const ctrl = new AbortController();

    fetchEventSource(`http://localhost:5000/tools/jobs/${jobId}/stream`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Accept': 'text/event-stream',
      },
      signal: ctrl.signal,
      onmessage(ev) {
        const data = JSON.parse(ev.data);
        
        if (data.status === 'output') {
          // Append live stdout/stderr log
          setLogs(prev => [...prev, { stream: data.stream, text: data.content }]);
        } else if (data.status === 'completed' || data.status === 'failed') {
          setStatus(data.status);
          ctrl.abort(); // Close connection
        }
      },
      onerror(err) {
        console.error("SSE Error:", err);
        ctrl.abort();
      }
    });

    return () => ctrl.abort();
  }, [jobId, apiKey]);

  return (
    <div className="terminal-window bg-black text-green-400 p-4 font-mono overflow-y-auto">
      {logs.map((log, i) => (
        <div key={i} className={log.stream === 'stderr' ? 'text-red-400' : ''}>
          {log.text}
        </div>
      ))}
      {status !== 'running' && <div className="text-blue-400">Process {status}.</div>}
    </div>
  );
}
```

---

## 5. Fetching Artifacts & Reports

Tools often generate structured artifacts (like Markdown summaries, Nmap XML files, or HTML reports). After a job is marked `completed`, you can retrieve the artifact.

```javascript
// Fetch memory history for the specific job
async function getJobArtifacts(apiKey, jobId) {
  // First, find the memory entry related to the job
  const response = await fetch(`http://localhost:5000/memory/search?query=${jobId}`, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
  
  const memories = await response.json();
  const jobMemory = memories.find(m => m.metadata?.job_id === jobId);
  
  if (jobMemory && jobMemory.metadata?.artifact_id) {
    const artifactId = jobMemory.metadata.artifact_id;
    // Download the artifact content
    const artifactResp = await fetch(`http://localhost:5000/artifacts/read?artifact_id=${artifactId}`, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    return await artifactResp.text(); // e.g., Markdown or HTML string
  }
  return null;
}
```

---

## 6. Webhook Configuration (Optional)

If the dashboard has a backend server (e.g., Next.js API Routes, Node.js, Express), you can configure the MCP server to send a webhook whenever a job finishes.

**Set this Environment Variable on the MCP Server:**
`MCP_SIEM_WEBHOOK_URL=https://your-dashboard-domain.com/api/webhooks/mcp`

Your endpoint will receive a `POST` request with the following JSON structure:

```json
{
  "event_type": "tool_execution",
  "tool_name": "recon.nmap_scan",
  "status": "success",
  "timestamp": "2026-07-23T12:00:00Z",
  "execution_time": 45.2,
  "summary": "Nmap scan completed successfully against 192.168.1.1",
  "job_id": "job_xyz123"
}
```

> [!NOTE]
> Webhooks are fire-and-forget. Ensure your receiving endpoint responds with `200 OK` quickly.

---

## Summary Checklist for Frontend Teams
- [ ] Implement Token Enrollment UI
- [ ] Build dynamic tool forms using the `/mcp` (`tools/list`) schema
- [ ] Integrate `@microsoft/fetch-event-source` for live SSE logs
- [ ] Render Markdown artifacts using a library like `react-markdown`
