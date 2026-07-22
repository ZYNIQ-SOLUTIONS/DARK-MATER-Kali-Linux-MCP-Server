"""
Brute Force / Credential Testing Tools Pack — brute.* category
Covers: Hydra multi-protocol, Medusa parallel brute force, CrackMapExec.
"""

import subprocess
import logging
import re
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


# Supported protocols
HYDRA_PROTOCOLS = {
    "ssh", "ftp", "http-get", "http-post-form", "https-get", "https-post-form",
    "smb", "rdp", "vnc", "telnet", "pop3", "imap", "smtp", "mysql", "mssql",
    "postgres", "oracle", "ldap2", "ldap3", "redis", "mongodb", "snmp"
}


# ──────────────────────────────────────────────────────────────────────────────
# brute.hydra — Multi-protocol password brute force
# ──────────────────────────────────────────────────────────────────────────────
def execute_hydra(server_id: str, args: Dict[str, Any]) -> _R:
    """Hydra credential testing — supports SSH, FTP, HTTP, SMB, RDP, databases."""
    t0 = time.time()
    target = args["target"]
    protocol = args.get("protocol", "ssh")
    port = args.get("port")
    username = args.get("username")
    username_list = args.get("username_list", "/usr/share/wordlists/metasploit/unix_users.txt")
    password = args.get("password")
    password_list = args.get("password_list", "/usr/share/wordlists/rockyou.txt.gz")
    tasks = args.get("tasks", 4)  # Parallel connections (keep low)
    timeout = args.get("timeout", 180)
    stop_on_success = args.get("stop_on_success", True)
    form_path = args.get("form_path", "/login")
    form_params = args.get("form_params", "username=^USER^&password=^PASS^")
    form_fail = args.get("form_fail", "Invalid")

    if protocol not in HYDRA_PROTOCOLS:
        return _R(-1, f"Protocol '{protocol}' not supported by this tool. "
                      f"Supported: {', '.join(sorted(HYDRA_PROTOCOLS))}")

    cmd = ["hydra", "-t", str(tasks), "-V"]

    # Username options
    if username:
        cmd += ["-l", username]
    else:
        cmd += ["-L", username_list]

    # Password options
    if password:
        cmd += ["-p", password]
    else:
        cmd += ["-P", password_list]

    if stop_on_success:
        cmd.append("-f")

    if port:
        cmd += ["-s", str(port)]

    # Protocol-specific
    if "http" in protocol:
        cmd += [target, protocol, f"{form_path}:{form_params}:{form_fail}"]
    else:
        cmd += [target, protocol]

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_hydra_output(r.stdout + r.stderr, target, protocol)
        success = [f for f in findings if f.get("type") == "valid_credential"]
        summary = (
            f"Hydra {protocol} on {target}: {len(success)} valid credential(s) found!"
            if success else f"Hydra {protocol} on {target}: no valid credentials found"
        )
        uri = _save_artifact(server_id, "hydra", r.stdout + r.stderr)
        _record(server_id, "brute_hydra", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"Hydra timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"Hydra error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# brute.medusa — Parallel password auditing
# ──────────────────────────────────────────────────────────────────────────────
def execute_medusa(server_id: str, args: Dict[str, Any]) -> _R:
    """Medusa parallel brute force tool — alternative to Hydra."""
    t0 = time.time()
    target = args["target"]
    protocol = args.get("protocol", "ssh")  # ssh, ftp, http, smb, etc.
    port = args.get("port")
    username = args.get("username")
    username_list = args.get("username_list", "/usr/share/wordlists/metasploit/unix_users.txt")
    password = args.get("password")
    password_list = args.get("password_list", "/usr/share/wordlists/fasttrack.txt")
    tasks = args.get("tasks", 4)
    timeout = args.get("timeout", 180)

    cmd = ["medusa", "-h", target, "-M", protocol, "-t", str(tasks), "-n", "1"]

    if username:
        cmd += ["-u", username]
    else:
        cmd += ["-U", username_list]

    if password:
        cmd += ["-p", password]
    else:
        cmd += ["-P", password_list]

    if port:
        cmd += ["-n", str(port)]

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_medusa_output(r.stdout + r.stderr, target, protocol)
        success = [f for f in findings if f.get("type") == "valid_credential"]
        summary = (
            f"Medusa {protocol} on {target}: {len(success)} valid credential(s) found!"
            if success else f"Medusa {protocol} on {target}: no valid credentials found"
        )
        uri = _save_artifact(server_id, "medusa", r.stdout + r.stderr)
        _record(server_id, "brute_medusa", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"Medusa timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"Medusa error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────────────────────
def _parse_hydra_output(output: str, target: str, protocol: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        # [21][ftp] host: 192.168.1.1   login: admin   password: password123
        m = re.search(
            r'\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)',
            line
        )
        if m:
            findings.append({
                "type": "valid_credential",
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "host": m.group(3),
                "username": m.group(4),
                "password": m.group(5),
                "severity": "critical",
            })
        elif "[ERROR]" in line:
            findings.append({"type": "error", "message": line.strip(), "severity": "low"})
        elif "successfully completed" in line.lower():
            findings.append({"type": "status", "message": line.strip(), "severity": "info"})
    return findings


def _parse_medusa_output(output: str, target: str, protocol: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        # ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: admin123 [SUCCESS]
        if "ACCOUNT FOUND" in line or "SUCCESS" in line:
            user_m = re.search(r'User:\s+(\S+)', line)
            pass_m = re.search(r'Password:\s+(\S+)', line)
            host_m = re.search(r'Host:\s+(\S+)', line)
            findings.append({
                "type": "valid_credential",
                "host": host_m.group(1) if host_m else target,
                "username": user_m.group(1) if user_m else "unknown",
                "password": pass_m.group(1) if pass_m else "unknown",
                "protocol": protocol,
                "severity": "critical",
            })
        elif "ERROR" in line.upper():
            findings.append({"type": "error", "message": line.strip(), "severity": "low"})
    return findings


# Export class wrapper
class BruteTools:
    execute_hydra = staticmethod(execute_hydra)
    execute_medusa = staticmethod(execute_medusa)
    HYDRA_PROTOCOLS = HYDRA_PROTOCOLS
