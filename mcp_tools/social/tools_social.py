"""
Social Engineering Tools Pack — social.* category
Covers: Gophish, SEToolkit, Maltego, PhishingFrenzy, Evilginx, KingPhisher.
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
# social.setoolkit
# ──────────────────────────────────────────────────────────────────────────────
def execute_setoolkit(server_id: str, args: Dict[str, Any]) -> _R:
    """Run SEToolkit."""
    t0 = time.time()
    
    # setoolkit is generally interactive, we'll run a non-interactive simulation or predefined attack
    cmd = ["setoolkit", "--no-update"]
    res = _run(cmd, timeout=1800)
    
    findings = []
    if "Social-Engineer Toolkit" in res.stdout:
        findings.append({"type": "setoolkit_started", "severity": "info", "description": "SEToolkit launched successfully"})
        
    uri = _save_artifact(server_id, "setoolkit", res.stdout)
    _record(server_id, "setoolkit", "SEToolkit execution completed", findings)
    return _R(res.returncode, "SEToolkit run finished", findings, uri, time.time() - t0)

# ──────────────────────────────────────────────────────────────────────────────
# social.evilginx
# ──────────────────────────────────────────────────────────────────────────────
def execute_evilginx(server_id: str, args: Dict[str, Any]) -> _R:
    """Run Evilginx."""
    t0 = time.time()
    
    phishlets = args.get("phishlets_path", "/usr/share/evilginx2/phishlets")
    cmd = ["evilginx2", "-p", phishlets]
    res = _run(cmd, timeout=3600)
    
    findings = []
    if "evilginx2" in res.stdout:
        findings.append({"type": "evilginx_started", "severity": "info", "description": "Evilginx launched successfully"})
        
    uri = _save_artifact(server_id, "evilginx", res.stdout)
    _record(server_id, "evilginx", "Evilginx execution completed", findings)
    return _R(res.returncode, "Evilginx run finished", findings, uri, time.time() - t0)

# Export class wrapper
class SocialTools:
    execute_setoolkit = staticmethod(execute_setoolkit)
    execute_evilginx = staticmethod(execute_evilginx)
