"""
Reconnaissance Tools Pack — recon.* category
Covers: Masscan, Nikto, Dirb, TheHarvester, Amass, Spiderfoot, Dnsrecon.
"""

import subprocess
import logging
import json
import time
import os
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
# recon.masscan
# ──────────────────────────────────────────────────────────────────────────────
def execute_masscan(server_id: str, args: Dict[str, Any]) -> _R:
    """Run masscan against target."""
    t0 = time.time()
    target = args.get("target")
    if not target:
        return _R(1, "Missing target argument")
        
    cmd = ["masscan", "-p", "1-65535", "--rate=1000", target]
    res = _run(cmd, timeout=600)
    
    findings = []
    if "Discovered open port" in res.stdout:
        findings.append({"type": "open_ports", "severity": "info", "description": "Found open ports via masscan"})
        
    uri = _save_artifact(server_id, "masscan", res.stdout)
    _record(server_id, "masscan", "Masscan execution completed", findings)
    return _R(res.returncode, f"Masscan run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# recon.nikto
# ──────────────────────────────────────────────────────────────────────────────
def execute_nikto(server_id: str, args: Dict[str, Any]) -> _R:
    """Run Nikto web vulnerability scanner."""
    t0 = time.time()
    target = args.get("target")
    if not target:
        return _R(1, "Missing target argument")
        
    cmd = ["nikto", "-h", target]
    res = _run(cmd, timeout=900)
    
    findings = []
    if "+ OSVDB" in res.stdout or "+ ERROR" not in res.stdout:
        findings.append({"type": "nikto_finding", "severity": "medium", "description": "Nikto found potential issues"})
        
    uri = _save_artifact(server_id, "nikto", res.stdout)
    _record(server_id, "nikto", "Nikto execution completed", findings)
    return _R(res.returncode, f"Nikto run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# recon.theharvester
# ──────────────────────────────────────────────────────────────────────────────
def execute_theharvester(server_id: str, args: Dict[str, Any]) -> _R:
    """Run theHarvester."""
    t0 = time.time()
    target = args.get("target")
    if not target:
        return _R(1, "Missing target argument")
        
    cmd = ["theHarvester", "-d", target, "-l", "500", "-b", "all"]
    res = _run(cmd, timeout=300)
    
    findings = []
    if "@" in res.stdout:
        findings.append({"type": "email_found", "severity": "info", "description": "Found emails associated with target"})
        
    uri = _save_artifact(server_id, "theharvester", res.stdout)
    _record(server_id, "theharvester", "theHarvester execution completed", findings)
    return _R(res.returncode, f"theHarvester run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# recon.amass
# ──────────────────────────────────────────────────────────────────────────────
def execute_amass(server_id: str, args: Dict[str, Any]) -> _R:
    """Run Amass enumeration."""
    t0 = time.time()
    target = args.get("target")
    if not target:
        return _R(1, "Missing target argument")
        
    cmd = ["amass", "enum", "-d", target]
    if args.get("passive"):
        cmd.append("-passive")
        
    res = _run(cmd, timeout=1800)
    
    findings = []
    if "FQDN" in res.stdout:
        findings.append({"type": "subdomain_found", "severity": "info", "description": "Found subdomains via amass"})
        
    uri = _save_artifact(server_id, "amass", res.stdout)
    _record(server_id, "amass", "Amass execution completed", findings)
    return _R(res.returncode, f"Amass run finished", findings, uri, time.time() - t0)

# Export class wrapper
class ReconTools:
    execute_masscan = staticmethod(execute_masscan)
    execute_nikto = staticmethod(execute_nikto)
    execute_theharvester = staticmethod(execute_theharvester)
    execute_amass = staticmethod(execute_amass)
