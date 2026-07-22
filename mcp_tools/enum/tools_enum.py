"""
Service Enumeration Tools Pack — enum.* category
Covers: SMB, SSH, HTTP headers, FTP, SMTP, LDAP, RDP, WhatWeb fingerprinting.
"""

import subprocess
import logging
import re
import json
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _run(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
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
# enum.smb — SMB/Samba enumeration via enum4linux-ng
# ──────────────────────────────────────────────────────────────────────────────
def execute_smb_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """Enumerate SMB shares, users, policies using enum4linux-ng."""
    t0 = time.time()
    target = args["target"]
    username = args.get("username", "")
    password = args.get("password", "")
    timeout = args.get("timeout", 120)
    all_enum = args.get("all", True)

    # Try enum4linux-ng first, fall back to enum4linux
    cmd = ["enum4linux-ng", "-A", target]
    if username:
        cmd += ["-u", username, "-p", password]

    try:
        r = _run(cmd, timeout + 15)
        dur = time.time() - t0

        # Fallback to classic enum4linux
        if r.returncode != 0 and "not found" in r.stderr:
            cmd2 = ["enum4linux", "-a", target]
            if username:
                cmd2 += ["-u", username, "-p", password]
            r = _run(cmd2, timeout + 15)
            dur = time.time() - t0

        findings = _parse_enum4linux_output(r.stdout + r.stderr, target)
        summary = (
            f"SMB enum on {target}: {len(findings)} findings (shares, users, policies)"
            if findings else f"SMB enum on {target}: no data retrieved"
        )
        uri = _save_artifact(server_id, "smb_enum", r.stdout + r.stderr)
        _record(server_id, "smb_enum", summary, findings)
        return _R(0 if findings else 1, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"SMB enum timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"SMB enum error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# enum.ssh — SSH configuration audit via ssh-audit
# ──────────────────────────────────────────────────────────────────────────────
def execute_ssh_audit(server_id: str, args: Dict[str, Any]) -> _R:
    """Audit SSH server configuration and cipher suites with ssh-audit."""
    t0 = time.time()
    target = args["target"]
    port = args.get("port", 22)
    timeout = args.get("timeout", 30)

    cmd = ["ssh-audit", "-p", str(port), target]
    try:
        r = _run(cmd, timeout + 10)
        dur = time.time() - t0
        findings = _parse_ssh_audit_output(r.stdout + r.stderr, target, port)
        crit = [f for f in findings if f.get("severity") in ("critical", "high")]
        summary = (
            f"SSH audit on {target}:{port}: {len(findings)} issues "
            f"({len(crit)} critical/high)"
        )
        uri = _save_artifact(server_id, "ssh_audit", r.stdout + r.stderr)
        _record(server_id, "ssh_audit", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"SSH audit timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"SSH audit error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# enum.http_headers — HTTP headers + technology detection
# ──────────────────────────────────────────────────────────────────────────────
def execute_http_headers(server_id: str, args: Dict[str, Any]) -> _R:
    """Retrieve HTTP headers and fingerprint web technologies with whatweb."""
    t0 = time.time()
    target = args["target"]
    timeout = args.get("timeout", 30)
    aggressive = args.get("aggressive", False)

    findings = []
    raw = []

    # 1. curl for raw headers
    curl_cmd = ["curl", "-skI", "--max-time", "10", target]
    try:
        cr = _run(curl_cmd, 15)
        raw.append(f"=== HTTP Headers ===\n{cr.stdout}")
        for line in cr.stdout.splitlines():
            if ":" in line and not line.startswith("HTTP"):
                k, v = line.split(":", 1)
                findings.append({
                    "type": "http_header",
                    "header": k.strip(),
                    "value": v.strip(),
                    "target": target,
                    "severity": _header_severity(k.strip()),
                })
    except Exception:
        pass

    # 2. whatweb for technology fingerprinting
    ww_cmd = ["whatweb", "--color=never", "-a", "3" if aggressive else "1", target]
    try:
        wr = _run(ww_cmd, timeout)
        raw.append(f"=== WhatWeb ===\n{wr.stdout}")
        findings += _parse_whatweb_output(wr.stdout, target)
    except subprocess.TimeoutExpired:
        raw.append("WhatWeb timed out")
    except Exception as e:
        raw.append(f"WhatWeb error: {e}")

    dur = time.time() - t0
    summary = f"HTTP enum on {target}: {len(findings)} headers/technologies identified"
    uri = _save_artifact(server_id, "http_headers", "\n".join(raw))
    _record(server_id, "http_enum", summary, findings)
    return _R(0 if findings else 1, summary, findings, uri, dur)


# ──────────────────────────────────────────────────────────────────────────────
# enum.ftp — FTP service enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_ftp_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """FTP enumeration: anonymous login, banner, file listing."""
    t0 = time.time()
    target = args["target"]
    port = args.get("port", 21)
    timeout = args.get("timeout", 30)

    cmd = ["nmap", "-sV", "-p", str(port),
           "--script=ftp-anon,ftp-bounce,ftp-syst,ftp-brute,banner",
           "-T3", "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 15)
        dur = time.time() - t0
        findings = _parse_nmap_script_output(r.stdout, target)
        summary = f"FTP enum on {target}:{port}: {len(findings)} findings"
        uri = _save_artifact(server_id, "ftp_enum", r.stdout + r.stderr)
        _record(server_id, "ftp_enum", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"FTP enum timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"FTP enum error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# enum.smtp — SMTP user enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_smtp_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """SMTP enumeration: user validation via VRFY/EXPN/RCPT."""
    t0 = time.time()
    target = args["target"]
    port = args.get("port", 25)
    users = args.get("users", ["admin", "root", "postmaster", "info", "test", "mail"])
    timeout = args.get("timeout", 30)

    cmd = ["nmap", "-sV", "-p", str(port),
           "--script=smtp-enum-users,smtp-commands,smtp-ntlm-info,banner",
           f"--script-args=smtp-enum-users.userlist={','.join(users)}",
           "-T3", "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 15)
        dur = time.time() - t0
        findings = _parse_nmap_script_output(r.stdout, target)
        summary = f"SMTP enum on {target}:{port}: {len(findings)} findings"
        uri = _save_artifact(server_id, "smtp_enum", r.stdout + r.stderr)
        _record(server_id, "smtp_enum", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"SMTP enum timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"SMTP enum error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# enum.ldap — LDAP enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_ldap_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """LDAP enumeration — base DN discovery, anonymous bind check."""
    t0 = time.time()
    target = args["target"]
    port = args.get("port", 389)
    base_dn = args.get("base_dn", "")
    timeout = args.get("timeout", 30)

    findings = []
    raw = []

    # nmap LDAP scripts
    cmd = ["nmap", "-sV", "-p", str(port),
           "--script=ldap-rootdse,ldap-search,ldap-brute",
           "-T3", "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 15)
        raw.append(r.stdout + r.stderr)
        findings += _parse_nmap_script_output(r.stdout, target)
    except Exception as e:
        raw.append(str(e))

    # ldapsearch anonymous query
    if base_dn:
        ls_cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}:{port}",
                  "-b", base_dn, "-s", "base"]
        try:
            lr = _run(ls_cmd, 20)
            raw.append(lr.stdout + lr.stderr)
            for line in lr.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    findings.append({"type": "ldap_attribute", "key": k.strip(),
                                     "value": v.strip(), "host": target})
        except Exception as e:
            raw.append(str(e))

    dur = time.time() - t0
    summary = f"LDAP enum on {target}:{port}: {len(findings)} attributes/findings"
    uri = _save_artifact(server_id, "ldap_enum", "\n".join(raw))
    _record(server_id, "ldap_enum", summary, findings)
    return _R(0 if findings else 1, summary, findings, uri, dur)


# ──────────────────────────────────────────────────────────────────────────────
# enum.rdp — RDP service enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_rdp_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """RDP service enumeration — NLA check, encryption level, etc."""
    t0 = time.time()
    target = args["target"]
    port = args.get("port", 3389)
    timeout = args.get("timeout", 30)

    cmd = ["nmap", "-sV", "-p", str(port),
           "--script=rdp-enum-encryption,rdp-vuln-ms12-020,rdp-enum-os",
           "-T3", "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 15)
        dur = time.time() - t0
        findings = _parse_nmap_script_output(r.stdout, target)
        summary = f"RDP enum on {target}:{port}: {len(findings)} findings"
        uri = _save_artifact(server_id, "rdp_enum", r.stdout + r.stderr)
        _record(server_id, "rdp_enum", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"RDP enum timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"RDP enum error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────────────────────
def _parse_enum4linux_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    # Shares
    for m in re.finditer(r'Mapping:\s+(\S+),\s+Type:\s+(\S+)', output):
        findings.append({"type": "smb_share", "name": m.group(1),
                         "share_type": m.group(2), "host": target})
    # Users
    for m in re.finditer(r'user:\[(\S+)\]', output):
        findings.append({"type": "smb_user", "username": m.group(1), "host": target})
    # Domain info
    for m in re.finditer(r'Domain Name:\s+(.+)', output):
        findings.append({"type": "domain_info", "domain": m.group(1).strip(), "host": target})
    # Password policy
    if "Password History" in output or "Minimum password" in output:
        findings.append({"type": "password_policy", "host": target,
                         "note": "Password policy information retrieved"})
    return findings


def _parse_ssh_audit_output(output: str, target: str, port: int) -> List[Dict[str, Any]]:
    findings = []
    severity_map = {"(crit)": "critical", "(warn)": "high", "(info)": "info", "(good)": "low"}
    for line in output.splitlines():
        line = line.strip()
        for tag, severity in severity_map.items():
            if tag in line:
                findings.append({
                    "type": "ssh_issue",
                    "severity": severity,
                    "description": re.sub(r'\x1b\[[0-9;]*m', '', line).strip(),
                    "host": target,
                    "port": port,
                })
                break
    return findings


def _parse_whatweb_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    # WhatWeb outputs: URL [status] technology[version], ...
    for line in output.splitlines():
        if "[" in line and target.split("://")[-1].split("/")[0] in line:
            m = re.search(r'\[(\d+)\s', line)
            status = int(m.group(1)) if m else None
            techs = re.findall(r'(\w[\w\s.-]*?)\[([^\]]+)\]', line)
            for tech, version in techs:
                tech = tech.strip()
                if tech and tech not in ("http", "https"):
                    findings.append({
                        "type": "web_technology",
                        "technology": tech,
                        "version": version,
                        "status_code": status,
                        "target": target,
                    })
    return findings


def _parse_nmap_script_output(xml_output: str, target: str) -> List[Dict[str, Any]]:
    """Extract nmap script results from XML output."""
    import xml.etree.ElementTree as ET
    findings = []
    if not xml_output or "<nmaprun" not in xml_output:
        return findings
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            addr = host.find(".//address[@addrtype='ipv4']")
            ip = addr.get("addr") if addr is not None else target
            for port in host.findall(".//port"):
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    output = script.get("output", "")
                    sev = "info"
                    if any(k in output.lower() for k in ["vulnerable", "anonymous", "allowed", "exposed"]):
                        sev = "high"
                    findings.append({
                        "type": "script_result",
                        "script": script_id,
                        "output": output[:500],
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "host": ip,
                        "severity": sev,
                    })
    except ET.ParseError:
        pass
    return findings


def _header_severity(header_name: str) -> str:
    """Rate HTTP headers by security significance."""
    high_risk_missing = {
        "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security",
        "Content-Security-Policy", "X-XSS-Protection"
    }
    info_headers = {"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}
    if header_name in info_headers:
        return "medium"  # Version disclosure
    return "info"


# Export class wrapper for registry
class EnumTools:
    execute_smb_enum = staticmethod(execute_smb_enum)
    execute_ssh_audit = staticmethod(execute_ssh_audit)
    execute_http_headers = staticmethod(execute_http_headers)
    execute_ftp_enum = staticmethod(execute_ftp_enum)
    execute_smtp_enum = staticmethod(execute_smtp_enum)
    execute_ldap_enum = staticmethod(execute_ldap_enum)
    execute_rdp_enum = staticmethod(execute_rdp_enum)
