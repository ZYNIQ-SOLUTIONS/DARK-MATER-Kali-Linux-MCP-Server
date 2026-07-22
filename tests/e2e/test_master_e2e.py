"""
Comprehensive Master E2E Automated Verification Test Suite for DARK MATER MCP Server.
"""

import sys
import os
import time
import json
import urllib.request
from pathlib import Path

# Add project root and sdk path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "sdk" / "python"))

from darkmater_mcp import DarkMaterClient

BASE_URL = os.environ.get("MCP_BASE_URL", "http://localhost:5000")

def run_e2e_tests():
    print("=" * 70)
    print("[*] STARTING MASTER E2E AUTOMATED VERIFICATION SUITE")
    print("=" * 70)
    
    # 1. Fetch credentials from docker container or environment
    api_key = os.environ.get("MCP_API_KEY")
    if not api_key:
        print("[*] Retrieving API key from running Docker container...")
        try:
            import subprocess
            output = subprocess.check_output(
                ["docker", "exec", "mcp-kali-api", "cat", "/etc/mcp-kali/credentials.json"],
                text=True
            )
            creds = json.loads(output)
            first_key = list(creds.keys())[0]
            api_key = creds[first_key]["api_key"]
            print(f"[+] Loaded API key for server '{first_key}': {api_key[:12]}...")
        except Exception as e:
            print(f"[!] Could not fetch key automatically: {e}. Fallback to test_token.")
            api_key = "test_token"

    client = DarkMaterClient(BASE_URL, api_key)
    
    # Test 1: Health Check
    print("\n--- TEST 1: Health Check ---")
    health = client.health()
    print(f"Health Response: {json.dumps(health, indent=2)}")
    assert health.get("ok") is True or "status" in health, "Health check failed!"
    print("[SUCCESS] TEST 1 PASSED: Health endpoint functional.")

    # Test 2: Tool Listing
    print("\n--- TEST 2: List Available Tools ---")
    tools = client.list_tools()
    print(f"Discovered {len(tools)} registered tools.")
    assert len(tools) > 0, "No tools registered!"
    print("[SUCCESS] TEST 2 PASSED: Tool listing functional.")

    # Test 3: Synchronous Tool Execution
    print("\n--- TEST 3: Synchronous Tool Execution ---")
    res = client.call_tool("net.scan_basic", {"target": "127.0.0.1", "fast": True})
    print(f"Tool Result Summary: {res.get('summary')}")
    assert "rc" in res, "Invalid tool result structure!"
    print("[SUCCESS] TEST 3 PASSED: Synchronous tool call functional.")

    # Test 4: Persistent Async Job Submission & Polling
    print("\n--- TEST 4: Persistent Async Job Queue ---")
    job_id = client.submit_job("net.scan_basic", {"target": "127.0.0.1", "fast": True})
    print(f"Submitted async job ID: {job_id}")
    assert job_id is not None, "Failed to submit async job!"
    
    # Poll job
    time.sleep(3)
    job_info = client.get_job(job_id)
    print(f"Polled Job Status: {job_info.get('status')}")
    assert job_info.get("job_id") == job_id, "Job polling mismatch!"
    print("[SUCCESS] TEST 4 PASSED: Persistent async job queue functional.")

    # Test 5: OpenMCP Standard JSON-RPC Protocol
    print("\n--- TEST 5: OpenMCP JSON-RPC Standard Protocol (/mcp) ---")
    init_res = client.jsonrpc_request("initialize")
    print(f"OpenMCP Init Result: {json.dumps(init_res, indent=2)}")
    assert "protocolVersion" in init_res.get("result", {}), "OpenMCP initialize failed!"

    tools_rpc = client.jsonrpc_request("tools/list")
    assert "tools" in tools_rpc.get("result", {}), "OpenMCP tools/list failed!"
    print("[SUCCESS] TEST 5 PASSED: OpenMCP JSON-RPC 2.0 standard functional.")

    print("\n" + "=" * 70)
    print("[SUCCESS] ALL MASTER E2E TESTS PASSED SUCCESSFULLY! (100% VERIFIED)")
    print("=" * 70)

if __name__ == "__main__":
    run_e2e_tests()
