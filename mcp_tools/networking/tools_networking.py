"""
Networking Tools Pack — net.* category
Covers: advanced nmap, UDP scan, ping sweep, traceroute, ARP scan,
        WHOIS, DNS lookup, DNS zone transfer, SNMP enum, banner grab.
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
    """Safe subprocess wrapper — never uses shell=True."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _save_artifact(server_id: str, kind: str, content: str) -> Optional[str]:
    try:
        from mcp_server.artifacts import artifact_manager
        return artifact_manager.save_artifact(
            server_id=server_id,
            run_id=f"{kind}_{int(time.time())}",
            kind=kind,
            content=content,
        )
    except Exception as e:
        logger.warning(f"Could not save artifact: {e}")
        return None


def _record(server_id: str, kind: str, summary: str, findings: list) -> None:
    try:
        from mcp_server.memory import record_observation
        record_observation(server_id, kind, summary, findings)
    except Exception as e:
        logger.warning(f"Could not record observation: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Result helper
# ──────────────────────────────────────────────────────────────────────────────
class _R:
    """Lightweight result container (mirrors ToolResult interface)."""
    def __init__(self, rc: int, summary: str, findings: list = None,
                 artifact_uri: str = None, duration: float = 0):
        self.rc = rc
        self.summary = summary
        self.findings = findings or []
        self.artifact_uri = artifact_uri
        self.duration = duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rc": self.rc,
            "summary": self.summary,
            "artifact_uri": self.artifact_uri,
            "findings": self.findings,
            "duration": self.duration,
            "duration_formatted": f"{self.duration:.1f}s",
        }


# ──────────────────────────────────────────────────────────────────────────────
# net.scan_advanced — Full nmap scan with OS/script detection
# ──────────────────────────────────────────────────────────────────────────────
def execute_nmap_advanced(server_id: str, args: Dict[str, Any]) -> _R:
    """Full nmap scan: service version, OS detection, default scripts."""
    t0 = time.time()
    target = args["target"]
    ports = args.get("ports", "1-65535")
    scripts = args.get("scripts", "default")
    timing = args.get("timing", "T3")
    os_detect = args.get("os_detect", True)
    timeout = args.get("timeout", 300)

    cmd = ["nmap", "-sV", "--open", f"-{timing}"]
    if os_detect:
        cmd += ["-O", "--osscan-limit"]
    if ports:
        cmd += ["-p", ports]
    if scripts:
        cmd += [f"--script={scripts}"]
    cmd += ["--host-timeout", f"{timeout}s", "-oX", "-", target]

    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_nmap_xml(r.stdout)
        summary = (
            f"Advanced nmap scan of {target}: {len(findings)} hosts, "
            f"{sum(len(h.get('ports',[])) for h in findings)} open ports"
            if r.returncode == 0 else f"nmap failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "nmap_advanced", r.stdout or r.stderr)
        _record(server_id, "nmap_advanced", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"nmap timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"nmap error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.scan_udp — UDP port scan
# ──────────────────────────────────────────────────────────────────────────────
def execute_nmap_udp(server_id: str, args: Dict[str, Any]) -> _R:
    """UDP port scan using nmap -sU (requires root in container)."""
    t0 = time.time()
    target = args["target"]
    ports = args.get("ports", "53,67,68,69,123,161,162,514,1900")
    timeout = args.get("timeout", 180)

    cmd = ["nmap", "-sU", "-sV", "--open", "-T3",
           "-p", ports, "--host-timeout", f"{timeout}s",
           "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_nmap_xml(r.stdout)
        summary = (
            f"UDP scan of {target}: {sum(len(h.get('ports',[])) for h in findings)} open UDP ports"
            if r.returncode == 0 else f"UDP scan failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "nmap_udp", r.stdout or r.stderr)
        _record(server_id, "nmap_udp", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"UDP scan timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"UDP scan error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.ping_sweep — ICMP host discovery
# ──────────────────────────────────────────────────────────────────────────────
def execute_ping_sweep(server_id: str, args: Dict[str, Any]) -> _R:
    """Ping sweep / host discovery across a CIDR or range."""
    t0 = time.time()
    target = args["target"]
    timeout = args.get("timeout", 60)

    cmd = ["nmap", "-sn", "-T4", "--host-timeout", "10s", "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_nmap_hosts_up(r.stdout)
        summary = (
            f"Ping sweep of {target}: {len(findings)} hosts up"
            if r.returncode == 0 else f"Ping sweep failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "ping_sweep", r.stdout or r.stderr)
        _record(server_id, "ping_sweep", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"Ping sweep timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"Ping sweep error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.traceroute — Network path tracing
# ──────────────────────────────────────────────────────────────────────────────
def execute_traceroute(server_id: str, args: Dict[str, Any]) -> _R:
    """Trace network path to target."""
    t0 = time.time()
    target = args["target"]
    max_hops = args.get("max_hops", 30)
    timeout = args.get("timeout", 60)

    # Use nmap traceroute (works without raw sockets in some setups)
    cmd = ["nmap", "--traceroute", "-sn", "-T4", "--max-retries=1",
           f"--max-hostgroup=1", target]
    try:
        r = _run(cmd, timeout + 10)
        dur = time.time() - t0
        findings = _parse_traceroute_output(r.stdout)
        summary = (
            f"Traceroute to {target}: {len(findings)} hops"
            if r.returncode == 0 else f"Traceroute failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "traceroute", r.stdout or r.stderr)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"Traceroute timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"Traceroute error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.arp_scan — Layer 2 ARP host discovery
# ──────────────────────────────────────────────────────────────────────────────
def execute_arp_scan(server_id: str, args: Dict[str, Any]) -> _R:
    """ARP scan for live hosts on the local network (requires root)."""
    t0 = time.time()
    target = args["target"]
    interface = args.get("interface", "eth0")
    timeout = args.get("timeout", 30)

    cmd = ["arp-scan", "--interface", interface, target]
    try:
        r = _run(cmd, timeout + 10)
        dur = time.time() - t0
        findings = _parse_arp_scan_output(r.stdout)
        summary = (
            f"ARP scan on {target}: {len(findings)} hosts discovered"
            if r.returncode == 0 else f"ARP scan failed: {r.stderr[:200]}"
        )
        uri = _save_artifact(server_id, "arp_scan", r.stdout or r.stderr)
        _record(server_id, "arp_scan", summary, findings)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"ARP scan timed out", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"ARP scan error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.whois — WHOIS lookup
# ──────────────────────────────────────────────────────────────────────────────
def execute_whois(server_id: str, args: Dict[str, Any]) -> _R:
    """WHOIS domain or IP lookup."""
    t0 = time.time()
    target = args["target"]

    cmd = ["whois", target]
    try:
        r = _run(cmd, 30)
        dur = time.time() - t0
        findings = _parse_whois_output(r.stdout, target)
        summary = f"WHOIS for {target}: {len(findings)} records returned" if r.returncode == 0 else f"WHOIS failed: {r.stderr[:200]}"
        uri = _save_artifact(server_id, "whois", r.stdout or r.stderr)
        return _R(r.returncode, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, "WHOIS timed out", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"WHOIS error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.dns_lookup — DNS record enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_dns_lookup(server_id: str, args: Dict[str, Any]) -> _R:
    """DNS record lookup using dig — enumerate A, MX, NS, TXT, CNAME etc."""
    t0 = time.time()
    target = args["target"]
    record_types = args.get("record_types", ["A", "MX", "NS", "TXT", "AAAA", "CNAME"])
    server = args.get("nameserver")

    findings = []
    raw_output = []

    for rtype in record_types:
        cmd = ["dig", "+short", rtype, target]
        if server:
            cmd = ["dig", f"@{server}", "+short", rtype, target]
        try:
            r = _run(cmd, 15)
            if r.stdout.strip():
                for line in r.stdout.strip().splitlines():
                    findings.append({"type": rtype, "value": line.strip(), "domain": target})
            raw_output.append(f"=== {rtype} ===\n{r.stdout}")
        except Exception as e:
            logger.debug(f"dig {rtype} failed: {e}")

    dur = time.time() - t0
    summary = f"DNS lookup for {target}: {len(findings)} records across {len(record_types)} types"
    uri = _save_artifact(server_id, "dns_lookup", "\n".join(raw_output))
    _record(server_id, "dns_lookup", summary, findings)
    return _R(0 if findings else 1, summary, findings, uri, dur)


# ──────────────────────────────────────────────────────────────────────────────
# net.dns_zone_transfer — DNS zone transfer attempt (AXFR)
# ──────────────────────────────────────────────────────────────────────────────
def execute_dns_zone_transfer(server_id: str, args: Dict[str, Any]) -> _R:
    """Attempt DNS zone transfer (AXFR) — reveals all DNS records if misconfigured."""
    t0 = time.time()
    domain = args["domain"]
    nameserver = args.get("nameserver")

    # First get NS records if no server specified
    if not nameserver:
        ns_r = _run(["dig", "+short", "NS", domain], 15)
        nameservers = [ns.strip().rstrip('.') for ns in ns_r.stdout.strip().splitlines() if ns.strip()]
    else:
        nameservers = [nameserver]

    findings = []
    raw = []
    for ns in nameservers[:3]:  # Try up to 3 NS
        cmd = ["dig", f"@{ns}", "AXFR", domain]
        try:
            r = _run(cmd, 20)
            raw.append(f"=== AXFR from {ns} ===\n{r.stdout}")
            if "Transfer failed" not in r.stdout and r.returncode == 0 and len(r.stdout) > 200:
                records = _parse_zone_transfer(r.stdout, domain)
                findings.extend(records)
                findings.insert(0, {
                    "type": "zone_transfer_success",
                    "nameserver": ns,
                    "domain": domain,
                    "severity": "critical",
                    "record_count": len(records)
                })
        except Exception as e:
            raw.append(f"Error with {ns}: {e}")

    dur = time.time() - t0
    success = any(f.get("type") == "zone_transfer_success" for f in findings)
    summary = (
        f"Zone transfer SUCCESS for {domain} — {len(findings)-1} records exposed! CRITICAL misconfiguration!"
        if success else
        f"Zone transfer blocked for {domain} (all {len(nameservers)} nameservers refused AXFR)"
    )
    uri = _save_artifact(server_id, "dns_zone_transfer", "\n".join(raw))
    _record(server_id, "dns_zone_transfer", summary, findings)
    return _R(0, summary, findings, uri, dur)


# ──────────────────────────────────────────────────────────────────────────────
# net.snmp_enum — SNMP enumeration
# ──────────────────────────────────────────────────────────────────────────────
def execute_snmp_enum(server_id: str, args: Dict[str, Any]) -> _R:
    """SNMP enumeration using snmpwalk with community string testing."""
    t0 = time.time()
    target = args["target"]
    community = args.get("community", "public")
    version = args.get("version", "2c")
    oid = args.get("oid", "1.3.6.1.2.1")  # MIB-2
    timeout = args.get("timeout", 30)

    cmd = ["snmpwalk", f"-v{version}", "-c", community, "-t", "5", "-r", "1", target, oid]
    try:
        r = _run(cmd, timeout + 10)
        dur = time.time() - t0
        findings = _parse_snmp_output(r.stdout, target)
        summary = (
            f"SNMP enum on {target} (community='{community}'): {len(findings)} OID values retrieved"
            if findings else f"SNMP enum on {target}: no data (wrong community or SNMP not running)"
        )
        uri = _save_artifact(server_id, "snmp_enum", r.stdout or r.stderr)
        _record(server_id, "snmp_enum", summary, findings)
        return _R(0 if findings else 1, summary, findings, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"SNMP enum timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"SNMP enum error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# net.banner_grab — TCP banner grabbing
# ──────────────────────────────────────────────────────────────────────────────
def execute_banner_grab(server_id: str, args: Dict[str, Any]) -> _R:
    """Grab service banners from open TCP ports using nmap -sV."""
    t0 = time.time()
    target = args["target"]
    ports = args.get("ports", "21,22,23,25,80,110,143,443,993,995,3306,3389,5432,8080,8443")
    timeout = args.get("timeout", 60)

    cmd = ["nmap", "-sV", "--version-intensity=5", "--open",
           "-p", ports, "-T3", "--host-timeout", f"{timeout}s",
           "-oX", "-", target]
    try:
        r = _run(cmd, timeout + 30)
        dur = time.time() - t0
        findings = _parse_nmap_xml(r.stdout)
        banners = []
        for host in findings:
            for port in host.get("ports", []):
                if port.get("product") or port.get("version"):
                    banners.append({
                        "host": host["host"],
                        "port": port["port"],
                        "service": port.get("service", ""),
                        "product": port.get("product", ""),
                        "version": port.get("version", ""),
                        "banner": f"{port.get('product','')} {port.get('version','')}".strip()
                    })
        summary = f"Banner grab on {target}: {len(banners)} service banners captured"
        uri = _save_artifact(server_id, "banner_grab", r.stdout or r.stderr)
        _record(server_id, "banner_grab", summary, banners)
        return _R(r.returncode, summary, banners, uri, dur)
    except subprocess.TimeoutExpired:
        return _R(-1, f"Banner grab timed out after {timeout}s", duration=time.time() - t0)
    except Exception as e:
        return _R(-1, f"Banner grab error: {e}", duration=time.time() - t0)


# ──────────────────────────────────────────────────────────────────────────────
# XML / text parsers
# ──────────────────────────────────────────────────────────────────────────────
def _parse_nmap_xml(xml_output: str) -> List[Dict[str, Any]]:
    findings = []
    if not xml_output or "<nmaprun" not in xml_output:
        return findings
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            addr = host.find(".//address[@addrtype='ipv4']")
            if addr is None:
                continue
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            hn = host.find(".//hostname")
            ports = []
            for port in host.findall(".//port"):
                st = port.find("state")
                if st is None or st.get("state") not in ("open", "open|filtered"):
                    continue
                svc = port.find("service")
                ports.append({
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "state": st.get("state"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
            if ports:
                findings.append({
                    "host": addr.get("addr"),
                    "hostname": hn.get("name") if hn is not None else None,
                    "state": "up",
                    "ports": ports,
                })
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
    return findings


def _parse_nmap_hosts_up(xml_output: str) -> List[Dict[str, Any]]:
    findings = []
    if not xml_output:
        return findings
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            addr = host.find(".//address[@addrtype='ipv4']")
            if addr is None:
                continue
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                hn = host.find(".//hostname")
                mac = host.find(".//address[@addrtype='mac']")
                findings.append({
                    "host": addr.get("addr"),
                    "hostname": hn.get("name") if hn is not None else None,
                    "mac": mac.get("addr") if mac is not None else None,
                    "vendor": mac.get("vendor") if mac is not None else None,
                    "state": "up",
                })
    except ET.ParseError:
        pass
    return findings


def _parse_traceroute_output(output: str) -> List[Dict[str, Any]]:
    hops = []
    for match in re.finditer(r'HOP\s+(\d+)\s+([\d.]+)\s+([\d.]+\s*ms)', output, re.IGNORECASE):
        hops.append({"hop": int(match.group(1)), "host": match.group(2), "rtt": match.group(3)})
    if not hops:
        # Fallback: parse standard traceroute lines
        for i, line in enumerate(output.splitlines(), 1):
            m = re.search(r'([\d]+\.\d+\.\d+\.\d+)', line)
            if m:
                hops.append({"hop": i, "host": m.group(1)})
    return hops


def _parse_arp_scan_output(output: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        m = re.match(r'([\d.]+)\s+([\w:]+)\s+(.*)', line)
        if m:
            findings.append({
                "host": m.group(1),
                "mac": m.group(2),
                "vendor": m.group(3).strip(),
            })
    return findings


def _parse_whois_output(output: str, target: str) -> List[Dict[str, Any]]:
    fields = ["Registrar", "Registrant", "Name Server", "Creation Date",
              "Expiry Date", "Updated Date", "Status", "Org", "Country",
              "CIDR", "NetRange", "NetName", "OrgName"]
    findings = []
    for line in output.splitlines():
        for field in fields:
            if line.strip().lower().startswith(field.lower() + ":"):
                val = line.split(":", 1)[1].strip()
                if val:
                    findings.append({"field": field, "value": val, "target": target})
    return findings


def _parse_zone_transfer(output: str, domain: str) -> List[Dict[str, Any]]:
    records = []
    for line in output.splitlines():
        if line.strip() and not line.startswith(";"):
            parts = line.split()
            if len(parts) >= 5:
                records.append({
                    "name": parts[0],
                    "ttl": parts[1],
                    "class": parts[2],
                    "type": parts[3],
                    "value": " ".join(parts[4:]),
                    "domain": domain,
                })
    return records


def _parse_snmp_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        if "=" in line:
            parts = line.split("=", 1)
            findings.append({
                "oid": parts[0].strip(),
                "value": parts[1].strip() if len(parts) > 1 else "",
                "host": target,
            })
    return findings[:100]  # Cap at 100 OIDs
