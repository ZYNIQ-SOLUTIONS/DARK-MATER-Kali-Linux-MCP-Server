"""
Vulnerability Scanning Tools Pack — vuln.* category
Covers: nmap NSE vulnerability scripts, searchsploit CVE/Exploit-DB search,
        web gobuster, sqlmap, whatweb (standalone).
"""

import subprocess
import logging
import re
import json
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _run(cmd: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
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
# vuln.nmap_scripts — nmap NSE vulnerability scan
# ──────────────────────────────────────────────────────────────────────────────
def execute_nmap_vuln_scripts(server_id: str, args: Dict[str, Any]) -> _R:
    """Run nmap with NSE vulnerability scripts against target."""
    t0 = time.time()
    target = args["target"]
    ports = args.get("ports", "")
    scripts = args.get("scripts", "vuln")  # vuln, safe, exploit, auth, etc.
    timeout = args.get("timeout", 300)

    cmd = ["nmap", "-sV", "--open", "-T3",
           "--script", scripts,
           "--host-timeout", f"{timeout}s",
           "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_nmap_vuln_xml(r.stdout, target)
        crit = [f for f in findings if f.get("severity") in ("critical", "high")]
        summary = (
            f"NSE vuln scan on {target}: {len(findings)} issues found "
            f"({len(crit)} high/critical)"
            if r.returncode == 0 else f"nmap vuln scan failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "nmap_vuln", r.stdout + r.stderr)
        _record(server_id, "vuln_scan", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"nmap vuln scan timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"nmap vuln scan error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# vuln.searchsploit — Search Exploit-DB by service/product name
# ──────────────────────────────────────────────────────────────────────────────
def execute_searchsploit(server_id: str, args: Dict[str, Any]) -> _R:
    """Search Exploit-DB (searchsploit) for known exploits matching a product/service."""
    t0 = time.time()
    query = args["query"]
    exclude_dos = args.get("exclude_dos", True)
    web_only = args.get("web_only", False)
    remote_only = args.get("remote_only", False)

    cmd = ["searchsploit", "--json", query]
    if exclude_dos:
        cmd += ["--exclude=dos"]
    if web_only:
        cmd += ["--type=webapps"]

    try:
        r = _run(cmd, 60)
        dur = time.time() - t0

        findings = []
        try:
            data = json.loads(r.stdout)
            for exploit in data.get("RESULTS_EXPLOIT", []):
                path = exploit.get("Path", "")
                title = exploit.get("Title", "")
                etype = exploit.get("Type", "")
                edb_id = exploit.get("EDB-ID", "")

                # Severity heuristic
                sev = "medium"
                if any(k in title.lower() for k in ["remote code", "rce", "command injection",
                                                       "buffer overflow", "privilege escalation"]):
                    sev = "critical"
                elif any(k in title.lower() for k in ["sql injection", "xss", "directory traversal",
                                                        "authentication bypass", "local file"]):
                    sev = "high"

                if remote_only and "Remote" not in title and "remote" not in path.lower():
                    continue

                findings.append({
                    "edb_id": edb_id,
                    "title": title,
                    "type": etype,
                    "path": path,
                    "severity": sev,
                    "query": query,
                    "url": f"https://www.exploit-db.com/exploits/{edb_id}"
                })
        except json.JSONDecodeError:
            # Fallback: text parsing
            for line in r.stdout.splitlines():
                if "|" in line and not line.startswith("-") and "Title" not in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 2:
                        findings.append({"title": parts[0], "path": parts[-1], "query": query})

        summary = (
            f"Searchsploit for '{query}': {len(findings)} exploits found in Exploit-DB"
            if findings else f"Searchsploit for '{query}': no matching exploits found"
        )
        uri = _save_artifact(server_id, "searchsploit", r.stdout + r.stderr)
        _record(server_id, "exploit_search", summary, findings)
        return _R(0 if findings else 1, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, "searchsploit timed out", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"searchsploit error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# web.gobuster — Directory/file/DNS brute force
# ──────────────────────────────────────────────────────────────────────────────
def execute_gobuster(server_id: str, args: Dict[str, Any]) -> _R:
    """Directory and file brute force using gobuster."""
    t0 = time.time()
    target = args["target"]
    mode = args.get("mode", "dir")  # dir | dns | vhost
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    extensions = args.get("extensions", "php,html,js,txt,json,xml,bak")
    threads = args.get("threads", 20)
    timeout = args.get("timeout", 180)
    status_codes = args.get("status_codes", "200,204,301,302,307,401,403")

    cmd = ["gobuster", mode,
           "-u", target,
           "-w", wordlist,
           "-t", str(threads),
           "--timeout", "10s",
           "-q",  # quiet mode (no progress bar)
           "-o", "-"]

    if mode == "dir":
        cmd += ["-s", status_codes]
        if extensions:
            cmd += ["-x", extensions]

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_gobuster_output(r.stdout, target)
        summary = (
            f"Gobuster ({mode}) on {target}: {len(findings)} paths found"
            if r.returncode == 0 else f"gobuster failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "gobuster", r.stdout + r.stderr)
        _record(server_id, "web_gobuster", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"gobuster timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"gobuster error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# web.sqlmap — SQL injection scanner
# ──────────────────────────────────────────────────────────────────────────────
def execute_sqlmap(server_id: str, args: Dict[str, Any]) -> _R:
    """SQL injection scanning using sqlmap."""
    t0 = time.time()
    target = args["target"]
    data = args.get("data")          # POST data string
    level = args.get("level", 1)     # 1-5
    risk = args.get("risk", 1)       # 1-3
    dbms = args.get("dbms")          # mysql, mssql, oracle, etc.
    technique = args.get("technique", "BEUSTQ")
    timeout = args.get("timeout", 180)
    batch = args.get("batch", True)  # Non-interactive

    cmd = [
        "sqlmap",
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--output-dir", "/tmp/sqlmap_out",
        "--forms",
    ]

    if batch:
        cmd.append("--batch")

    if data:
        cmd += ["--data", data]

    if dbms:
        cmd += ["--dbms", dbms]

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_sqlmap_output(r.stdout + r.stderr, target)
        injected = [f for f in findings if f.get("type") == "injection"]
        summary = (
            f"SQLmap on {target}: {len(injected)} injection points found"
            if r.returncode == 0 else f"sqlmap failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "sqlmap", r.stdout + r.stderr)
        _record(server_id, "sql_injection", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"sqlmap timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"sqlmap error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────────────────────
def _parse_nmap_vuln_xml(xml_output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    if not xml_output or "<nmaprun" not in xml_output:
        return findings
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            addr = host.find(".//address[@addrtype='ipv4']")
            ip = addr.get("addr") if addr is not None else target
            for port in host.findall(".//port"):
                pnum = int(port.get("portid", 0))
                proto = port.get("protocol", "tcp")
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    output_text = script.get("output", "")
                    # Determine severity
                    sev = "info"
                    ol = output_text.lower()
                    if "vulnerable" in ol or "exploit" in ol:
                        sev = "critical" if "remote code" in ol or "rce" in ol else "high"
                    elif "safe" in ol:
                        sev = "low"

                    findings.append({
                        "type": "nse_vuln",
                        "script": script_id,
                        "output": output_text[:1000],
                        "host": ip,
                        "port": pnum,
                        "protocol": proto,
                        "severity": sev,
                    })
                    # Parse nested table elements for CVEs
                    for elem in script.iter("elem"):
                        key = elem.get("key", "")
                        val = elem.text or ""
                        if "cve" in key.lower() or "CVE" in val:
                            findings.append({
                                "type": "cve",
                                "cve": val.strip(),
                                "script": script_id,
                                "host": ip,
                                "port": pnum,
                                "severity": "high",
                            })
    except ET.ParseError as e:
        logger.error(f"vuln XML parse error: {e}")
    return findings


def _parse_gobuster_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        # Format: /path (Status: 200) [Size: 1234]
        m = re.match(r'^(/[^\s]*)\s*(?:\(Status:\s*(\d+)\))?\s*(?:\[Size:\s*(\d+)\])?', line)
        if m:
            path, status, size = m.group(1), m.group(2), m.group(3)
            sev = "info"
            if status in ("200", "204"):
                sev = "medium"
            elif status in ("401", "403"):
                sev = "low"
            findings.append({
                "type": "directory_found",
                "path": path,
                "url": target.rstrip("/") + path,
                "status_code": int(status) if status else None,
                "size": int(size) if size else None,
                "severity": sev,
            })
    return findings


def _parse_sqlmap_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        if "injectable" in line.lower() or "injection point" in line.lower():
            findings.append({"type": "injection", "description": line.strip(),
                             "severity": "critical", "target": target})
        elif "Parameter:" in line:
            m = re.search(r'Parameter:\s+(\S+)', line)
            if m:
                findings.append({"type": "parameter", "name": m.group(1),
                                  "target": target, "severity": "high"})
        elif "Type:" in line and "'" in line:
            findings.append({"type": "technique", "description": line.strip(),
                              "target": target, "severity": "high"})
        elif "[INFO] the back-end DBMS is" in line:
            db = line.split("is")[-1].strip()
            findings.append({"type": "dbms_detected", "dbms": db,
                              "target": target, "severity": "medium"})
    return findings


# Export class wrapper
class VulnTools:
    execute_nmap_vuln_scripts = staticmethod(execute_nmap_vuln_scripts)
    execute_searchsploit = staticmethod(execute_searchsploit)
    execute_gobuster = staticmethod(execute_gobuster)
    execute_sqlmap = staticmethod(execute_sqlmap)
