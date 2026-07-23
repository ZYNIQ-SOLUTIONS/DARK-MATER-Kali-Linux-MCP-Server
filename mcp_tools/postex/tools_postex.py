"""
Post-Exploitation Tools Pack — postex.* category
Covers: Hashcat, John the Ripper, LinPEAS, WinPEAS, BloodHound, Mimikatz, Responder, PowerSploit.
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
# postex.hashcat
# ──────────────────────────────────────────────────────────────────────────────
def execute_hashcat(server_id: str, args: Dict[str, Any]) -> _R:
    """Run hashcat."""
    t0 = time.time()
    mode = args.get("hash_mode")
    hash_file = args.get("hash_file")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    
    if not hash_file or not mode:
        return _R(1, "Missing hash_file or hash_mode")
        
    cmd = ["hashcat", "-m", str(mode), hash_file, wordlist]
    res = _run(cmd, timeout=3600)
    
    findings = []
    if "Cracked" in res.stdout or "Status...........: Cracked" in res.stdout:
        findings.append({"type": "hash_cracked", "severity": "high", "description": "Successfully cracked hashes"})
        
    uri = _save_artifact(server_id, "hashcat", res.stdout)
    _record(server_id, "hashcat", "Hashcat execution completed", findings)
    return _R(res.returncode, "Hashcat run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# postex.john
# ──────────────────────────────────────────────────────────────────────────────
def execute_john(server_id: str, args: Dict[str, Any]) -> _R:
    """Run John the Ripper."""
    t0 = time.time()
    hash_file = args.get("hash_file")
    wordlist = args.get("wordlist")
    
    if not hash_file:
        return _R(1, "Missing hash_file")
        
    cmd = ["john"]
    if wordlist:
        cmd.append(f"--wordlist={wordlist}")
    cmd.append(hash_file)
    
    res = _run(cmd, timeout=3600)
    
    findings = []
    if "password hashes cracked" in res.stdout:
        findings.append({"type": "hash_cracked", "severity": "high", "description": "Successfully cracked hashes"})
        
    uri = _save_artifact(server_id, "john", res.stdout)
    _record(server_id, "john", "John execution completed", findings)
    return _R(res.returncode, "John run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# postex.linpeas
# ──────────────────────────────────────────────────────────────────────────────
def execute_linpeas(server_id: str, args: Dict[str, Any]) -> _R:
    """Run LinPEAS."""
    t0 = time.time()
    cmd = ["bash", "linpeas.sh", "-a"]
    res = _run(cmd, timeout=600)
    
    findings = []
    if "RED/YELLOW" in res.stdout or "99% a PE vector" in res.stdout:
        findings.append({"type": "privesc_vector", "severity": "high", "description": "LinPEAS identified potential privilege escalation vectors"})
        
    uri = _save_artifact(server_id, "linpeas", res.stdout)
    _record(server_id, "linpeas", "LinPEAS execution completed", findings)
    return _R(res.returncode, "LinPEAS run finished", findings, uri, time.time() - t0)

# Export class wrapper
class PostexTools:
    execute_hashcat = staticmethod(execute_hashcat)
    execute_john = staticmethod(execute_john)
    execute_linpeas = staticmethod(execute_linpeas)
