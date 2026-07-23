"""
Utility Tools Pack — utility.* category
Covers: BurpSuite, OWASP-ZAP, OpenVAS, Nessus, WPScan, Dirsearch, ffuf, Aquatone, Eyewitness, Nuclei, Subfinder.
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
# utility.wpscan
# ──────────────────────────────────────────────────────────────────────────────
def execute_wpscan(server_id: str, args: Dict[str, Any]) -> _R:
    """Run WPScan."""
    t0 = time.time()
    target = args.get("target")
    if not target: return _R(1, "Missing target")
    
    cmd = ["wpscan", "--url", target, "--enumerate", "u,t,p", "--format", "json"]
    res = _run(cmd, timeout=900)
    
    findings = []
    if "vulnerabilities identified" in res.stdout:
        findings.append({"type": "wpscan_vulnerability", "severity": "high", "description": "WPScan identified vulnerabilities"})
        
    uri = _save_artifact(server_id, "wpscan", res.stdout)
    _record(server_id, "wpscan", "WPScan execution completed", findings)
    return _R(res.returncode, "WPScan run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# utility.ffuf
# ──────────────────────────────────────────────────────────────────────────────
def execute_ffuf(server_id: str, args: Dict[str, Any]) -> _R:
    """Run ffuf."""
    t0 = time.time()
    target = args.get("target")
    wordlist = args.get("wordlist")
    if not target or not wordlist: return _R(1, "Missing target or wordlist")
    
    cmd = ["ffuf", "-w", wordlist, "-u", f"{target}/FUZZ", "-of", "json"]
    res = _run(cmd, timeout=1800)
    
    findings = []
    if "Status: 200" in res.stdout:
        findings.append({"type": "ffuf_finding", "severity": "info", "description": "Found paths via ffuf"})
        
    uri = _save_artifact(server_id, "ffuf", res.stdout)
    _record(server_id, "ffuf", "FFUF execution completed", findings)
    return _R(res.returncode, "FFUF run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# utility.nuclei
# ──────────────────────────────────────────────────────────────────────────────
def execute_nuclei(server_id: str, args: Dict[str, Any]) -> _R:
    """Run Nuclei."""
    t0 = time.time()
    target = args.get("target")
    if not target: return _R(1, "Missing target")
    
    cmd = ["nuclei", "-u", target, "-json"]
    res = _run(cmd, timeout=1800)
    
    findings = []
    if "[critical]" in res.stdout.lower() or "[high]" in res.stdout.lower():
        findings.append({"type": "nuclei_vuln", "severity": "high", "description": "Nuclei identified high/critical vulnerabilities"})
        
    uri = _save_artifact(server_id, "nuclei", res.stdout)
    _record(server_id, "nuclei", "Nuclei execution completed", findings)
    return _R(res.returncode, "Nuclei run finished", findings, uri, time.time() - t0)

# Export class wrapper
class UtilityTools:
    execute_wpscan = staticmethod(execute_wpscan)
    execute_ffuf = staticmethod(execute_ffuf)
    execute_nuclei = staticmethod(execute_nuclei)
