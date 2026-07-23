"""
Wireless Tools Pack — wireless.* category
Covers: Aircrack-ng suite, Bettercap, Kismet, Wifite, Reaver, Bluez.
"""

import subprocess
import logging
import json
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def _run(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

def _save_artifact(server_id: str, kind: str, content: str) -> Optional[str]:
    try:
        from mcp_server.artifacts import artifact_manager
        return artifact_manager.save_artifact(
            server_id=server_id, run_id=f"{kind}_{int(time.time())}",
            kind=kind, content=content)
    except Exception as e:
        logger.warning(f"Artifact save failed: {e}")
        return None

def _record(server_id: str, kind: str, summary: str, findings: list) -> None:
    try:
        from mcp_server.memory import record_observation
        record_observation(server_id, kind, summary, findings)
    except Exception:
        pass

class _R:
    def __init__(self, rc, summary, findings=None, artifact_uri=None, duration=0):
        self.rc = rc; self.summary = summary; self.findings = findings or []
        self.artifact_uri = artifact_uri; self.duration = duration

    def to_dict(self):
        return {"rc": self.rc, "summary": self.summary, "artifact_uri": self.artifact_uri,
                "findings": self.findings, "duration": self.duration,
                "duration_formatted": f"{self.duration:.1f}s"}

# ──────────────────────────────────────────────────────────────────────────────
# wireless.aircrack-ng
# ──────────────────────────────────────────────────────────────────────────────
def execute_aircrack_ng(server_id: str, args: Dict[str, Any]) -> _R:
    """Run aircrack-ng tools."""
    t0 = time.time()
    tool = args.get("tool", "aircrack") # airmon, airodump, aireplay, aircrack
    
    cmd = []
    if tool == "airmon":
        interface = args.get("interface", "wlan0")
        cmd = ["airmon-ng", "start", interface]
    elif tool == "airodump":
        interface = args.get("interface", "wlan0mon")
        bssid = args.get("bssid")
        channel = args.get("channel")
        output = args.get("output_prefix", "dump")
        cmd = ["airodump-ng"]
        if channel: cmd.extend(["-c", channel])
        if bssid: cmd.extend(["--bssid", bssid])
        cmd.extend(["-w", output, interface])
    elif tool == "aireplay":
        interface = args.get("interface", "wlan0mon")
        bssid = args.get("bssid")
        client = args.get("client")
        if not bssid or not client: return _R(1, "Missing bssid or client for aireplay")
        cmd = ["aireplay-ng", "-0", "5", "-a", bssid, "-c", client, interface]
    elif tool == "aircrack":
        capture = args.get("capture_file")
        wordlist = args.get("wordlist")
        if not capture or not wordlist: return _R(1, "Missing capture or wordlist for aircrack")
        cmd = ["aircrack-ng", "-w", wordlist, capture]
    else:
        return _R(1, f"Unknown aircrack tool: {tool}")
        
    res = _run(cmd, timeout=3600)
    
    findings = []
    if "KEY FOUND!" in res.stdout:
        findings.append({"type": "key_cracked", "severity": "critical", "description": "Wireless key successfully cracked"})
        
    uri = _save_artifact(server_id, f"aircrack_{tool}", res.stdout)
    _record(server_id, "aircrack-ng", f"Aircrack-ng {tool} execution completed", findings)
    return _R(res.returncode, f"Aircrack-ng {tool} run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# wireless.wifite
# ──────────────────────────────────────────────────────────────────────────────
def execute_wifite(server_id: str, args: Dict[str, Any]) -> _R:
    """Run wifite automated wireless attack tool."""
    t0 = time.time()
    
    cmd = ["wifite", "--no-wps"]
    wordlist = args.get("wordlist")
    if wordlist:
        cmd.extend(["--dict", wordlist])
        
    res = _run(cmd, timeout=7200)
    
    findings = []
    if "cracked" in res.stdout.lower():
        findings.append({"type": "network_cracked", "severity": "critical", "description": "Wifite successfully cracked a network"})
        
    uri = _save_artifact(server_id, "wifite", res.stdout)
    _record(server_id, "wifite", "Wifite execution completed", findings)
    return _R(res.returncode, "Wifite run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# wireless.bluez
# ──────────────────────────────────────────────────────────────────────────────
def execute_bluez(server_id: str, args: Dict[str, Any]) -> _R:
    """Run bluez bluetooth utilities."""
    t0 = time.time()
    tool = args.get("tool", "hcitool")
    
    cmd = []
    if tool == "hcitool":
        cmd = ["hcitool", "scan"]
    elif tool == "l2ping":
        target = args.get("target_mac")
        if not target: return _R(1, "Missing target_mac for l2ping")
        cmd = ["l2ping", target]
    else:
        return _R(1, f"Unknown bluez tool: {tool}")
        
    res = _run(cmd, timeout=300)
    
    findings = []
    if ":" in res.stdout and tool == "hcitool":
        findings.append({"type": "bluetooth_device", "severity": "info", "description": "Found bluetooth devices"})
        
    uri = _save_artifact(server_id, f"bluez_{tool}", res.stdout)
    _record(server_id, "bluez", f"Bluez {tool} execution completed", findings)
    return _R(res.returncode, f"Bluez {tool} run finished", findings, uri, time.time() - t0)

# Export class wrapper
class WirelessTools:
    execute_aircrack_ng = staticmethod(execute_aircrack_ng)
    execute_wifite = staticmethod(execute_wifite)
    execute_bluez = staticmethod(execute_bluez)
