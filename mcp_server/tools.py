"""
Tools module for MCP Kali Server.
Provides schema-validated, safe execution of security testing tools.
"""

import subprocess
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import shlex
import time

from .util import validate_tool_args, generate_run_id, format_duration, truncate_output
from .scope import validate_scope_and_destructiveness
from .artifacts import save_artifact
from .memory import record_observation
from .jobs import job_manager

logger = logging.getLogger(__name__)

class ToolResult:
    """Result of a tool execution."""
    
    def __init__(self, rc: int, summary: str, artifact_uri: Optional[str] = None, 
                 findings: Optional[List[Dict[str, Any]]] = None, duration: float = 0):
        self.rc = rc
        self.summary = summary
        self.artifact_uri = artifact_uri
        self.findings = findings or []
        self.duration = duration
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "rc": self.rc,
            "summary": self.summary,
            "artifact_uri": self.artifact_uri,
            "findings": self.findings,
            "duration": self.duration,
            "duration_formatted": format_duration(self.duration)
        }

class ToolRegistry:
    """Registry of available tools and their metadata."""
    
    def __init__(self):
        self.tools = {
            "net.scan_basic": {
                "name": "net.scan_basic",
                "description": "Basic network scan using nmap with safety constraints",
                "schema": "/schemas/tools/net_scan_basic.json",
                "executor": self._execute_nmap_basic
            }
        }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """
        Get list of available tools with metadata.
        
        Returns:
            List of tool metadata dictionaries
        """
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "schema": tool["schema"]
            }
            for tool in self.tools.values()
        ]
    
    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get tool metadata by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool metadata or None if not found
        """
        return self.tools.get(name)
    
    def register_tool(self, name: str, description: str, category: str, schema_file: str, executor):
        """
        Register a new tool with the registry.
        
        Args:
            name: Tool name (e.g., "web.nikto")
            description: Tool description
            category: Tool category for organization
            schema_file: Schema filename (e.g., "web_nikto.json")
            executor: Callable that executes the tool
        """
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "schemas", "tools", schema_file)
        if not os.path.exists(schema_path):
            logger.error(f"Schema file not found for tool {name}: {schema_path}. Skipping registration.")
            return

        self.tools[name] = {
            "name": name,
            "description": description,
            "category": category,
            "schema": f"/schemas/tools/{schema_file}",
            "executor": executor
        }
        logger.debug(f"Registered tool: {name} ({category})")
    
    def _execute_nmap_basic(self, server_id: str, args: Dict[str, Any]) -> ToolResult:
        """
        Execute basic nmap scan safely.
        
        Args:
            server_id: Server ID for artifact storage
            args: Validated tool arguments
            
        Returns:
            ToolResult with scan results
        """
        start_time = time.time()
        run_id = generate_run_id()
        
        try:
            target = args["target"]
            ports = args.get("ports", "")
            fast = args.get("fast", True)
            
            # Build nmap command safely (no shell injection)
            cmd = ["nmap", "-sV", "--open"]
            
            # Add fast scan option
            if fast:
                cmd.append("-F")
                
            # Add port specification
            if ports:
                cmd.extend(["-p", ports])
                
            # Add timing and timeout options for safety
            cmd.extend(["-T3", "--host-timeout", "5m"])
            
            # Output in XML format for parsing
            cmd.append("-oX")
            cmd.append("-")  # Output to stdout
            
            # Add target last
            cmd.append(target)
            
            logger.info(f"Executing nmap scan: {' '.join(cmd[:-1])} [target]")
            
            # Execute with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                check=False
            )
            
            duration = time.time() - start_time
            
            # Parse XML output
            findings = []
            if result.stdout and result.returncode == 0:
                findings = self._parse_nmap_xml(result.stdout)
            
            # Create summary
            if result.returncode == 0:
                if findings:
                    open_ports = sum(len(host.get("ports", [])) for host in findings)
                    summary = f"Scan completed successfully. Found {len(findings)} hosts with {open_ports} open ports."
                else:
                    summary = "Scan completed successfully. No open ports found."
            else:
                summary = f"Scan failed with return code {result.returncode}"
                if result.stderr:
                    summary += f": {result.stderr[:200]}"
            
            # Save artifact
            artifact_uri = None
            if result.stdout:
                artifact_data = {
                    "command": " ".join(cmd[:-1]) + " [target]",
                    "target": target,
                    "xml_output": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                    "duration": duration
                }
                artifact_uri = save_artifact(server_id, run_id, "nmap_scan", artifact_data)
            
            # Record observation in memory
            if findings:
                observation_summary = f"Nmap scan of {target} found {len(findings)} hosts"
                record_observation(server_id, "network_scan", observation_summary, findings)
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            summary = f"Scan timed out after {format_duration(duration)}"
            logger.warning(f"Nmap scan timed out: {target}")
            
            return ToolResult(
                rc=-1,
                summary=summary,
                duration=duration
            )
            
        except Exception as e:
            duration = time.time() - start_time
            summary = f"Scan failed: {str(e)}"
            logger.error(f"Nmap scan error: {e}")
            
            return ToolResult(
                rc=-1,
                summary=summary,
                duration=duration
            )
    
    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output to extract structured findings.
        
        Args:
            xml_output: XML output from nmap
            
        Returns:
            List of host findings with ports and services
        """
        try:
            root = ET.fromstring(xml_output)
            findings = []
            
            for host in root.findall("host"):
                # Get host address
                address_elem = host.find(".//address[@addrtype='ipv4']")
                if address_elem is None:
                    continue
                    
                host_ip = address_elem.get("addr")
                
                # Get hostname if available
                hostname_elem = host.find(".//hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None
                
                # Get host state
                status_elem = host.find("status")
                host_state = status_elem.get("state") if status_elem is not None else "unknown"
                
                if host_state != "up":
                    continue
                
                # Get ports
                ports = []
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        # Get port state
                        state_elem = port.find("state")
                        port_state = state_elem.get("state") if state_elem is not None else "unknown"
                        
                        if port_state not in ["open", "open|filtered"]:
                            continue
                        
                        # Get service info
                        service_elem = port.find("service")
                        service_name = service_elem.get("name") if service_elem is not None else "unknown"
                        service_version = service_elem.get("version") if service_elem is not None else ""
                        service_product = service_elem.get("product") if service_elem is not None else ""
                        
                        port_info = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": port_state,
                            "service": service_name,
                            "version": service_version,
                            "product": service_product
                        }
                        ports.append(port_info)
                
                if ports:  # Only include hosts with open ports
                    host_info = {
                        "host": host_ip,
                        "hostname": hostname,
                        "state": host_state,
                        "ports": ports
                    }
                    findings.append(host_info)
            
            logger.debug(f"Parsed {len(findings)} hosts from nmap XML")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return []

# Global tool registry instance
tool_registry = ToolRegistry()

def list_tools() -> List[Dict[str, Any]]:
    """
    Get list of available tools.
    
    Returns:
        List of tool metadata
    """
    return tool_registry.list_tools()

def call_tool(server_id: str, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a tool with validation and safety checks.
    
    Args:
        server_id: Server ID for authentication and artifact storage
        name: Tool name to execute
        args: Tool arguments
        
    Returns:
        Tool execution result dictionary
    """
    try:
        # Get tool metadata
        tool = tool_registry.get_tool(name)
        if not tool:
            return {
                "rc": -1,
                "summary": f"Tool not found: {name}",
                "error": "TOOL_NOT_FOUND"
            }
        
        # Validate arguments against schema
        is_valid, validation_error = validate_tool_args(name, args)
        if not is_valid:
            return {
                "rc": -1,
                "summary": f"Invalid arguments: {validation_error}",
                "error": "VALIDATION_FAILED"
            }
        
        # Check scope and destructiveness
        is_allowed, scope_error = validate_scope_and_destructiveness(name, args)
        if not is_allowed:
            return {
                "rc": -1,
                "summary": f"Operation not allowed: {scope_error}",
                "error": "SCOPE_VIOLATION"
            }
        
        # Execute tool
        executor = tool["executor"]
        result = executor(server_id, args)
        
        # Convert to dictionary and add metadata
        result_dict = result.to_dict()
        result_dict["tool_name"] = name
        result_dict["executed_at"] = datetime.now(timezone.utc).isoformat()
        result_dict["server_id"] = server_id
        
        logger.info(f"Tool {name} executed successfully for server {server_id}")
        return result_dict
        
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}")
        return {
            "rc": -1,
            "summary": f"Tool execution failed: {str(e)}",
            "error": "EXECUTION_FAILED"
        }

def call_tool_async(server_id: str, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a tool asynchronously by submitting it to the job manager.
    
    Args:
        server_id: Server ID for authentication and artifact storage
        name: Tool name to execute
        args: Tool arguments
        
    Returns:
        Job submission result dictionary
    """
    try:
        # Get tool metadata
        tool = tool_registry.get_tool(name)
        if not tool:
            return {
                "rc": -1,
                "summary": f"Tool not found: {name}",
                "error": "TOOL_NOT_FOUND"
            }
        
        # Validate arguments against schema
        is_valid, validation_error = validate_tool_args(name, args)
        if not is_valid:
            return {
                "rc": -1,
                "summary": f"Invalid arguments: {validation_error}",
                "error": "VALIDATION_FAILED"
            }
        
        # Check scope and destructiveness
        is_allowed, scope_error = validate_scope_and_destructiveness(name, args)
        if not is_allowed:
            return {
                "rc": -1,
                "summary": f"Operation not allowed: {scope_error}",
                "error": "SCOPE_VIOLATION"
            }
        
        # Submit to job manager
        executor = tool["executor"]
        job_id = job_manager.submit_job(server_id, name, args, executor)
        
        return {
            "job_id": job_id,
            "status": "queued",
            "tool_name": name,
            "message": "Job submitted successfully"
        }
        
    except Exception as e:
        logger.error(f"Error submitting async tool {name}: {e}")
        return {
            "rc": -1,
            "summary": f"Tool submission failed: {str(e)}",
            "error": "SUBMISSION_FAILED"
        }

# Extended Tool Implementations for Phase 2

class WebSecurityTools:
    """Web application security testing tools."""
    
    @staticmethod
    def execute_nikto_scan(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute Nikto web vulnerability scanner."""
        try:
            target = args["target"]
            port = args.get("port")
            ssl = args.get("ssl", False)
            timeout = args.get("timeout", 120)
            tuning = args.get("tuning")
            
            # Build nikto command
            cmd = ["nikto", "-h", target, "-Format", "xml", "-output", "-"]
            
            if port:
                cmd.extend(["-p", str(port)])
            
            if ssl:
                cmd.append("-ssl")
            
            if tuning:
                cmd.extend(["-T", tuning])
            
            # Add timeout
            cmd.extend(["-timeout", str(timeout)])
            
            # Execute command
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,  # Add buffer for timeout
                check=False
            )
            duration = time.time() - start_time
            
            # Parse results
            findings = WebSecurityTools._parse_nikto_output(result.stdout)
            
            # Generate summary
            if result.returncode == 0:
                summary = f"Nikto scan completed. Found {len(findings)} potential issues on {target}"
                if port:
                    summary += f" (port {port})"
            else:
                summary = f"Nikto scan failed for {target}: {result.stderr.strip()}"
                findings = []
            
            # Store artifact
            artifact_uri = None
            if result.stdout:
                from .artifacts import artifact_manager
                artifact_uri = artifact_manager.save_artifact(
                    server_id=server_id,
                    run_id=f"nikto_{int(time.time())}",
                    kind="nikto_scan",
                    content=result.stdout
                )
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"Nikto scan timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"Nikto execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"Nikto scan failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def _parse_nikto_output(xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nikto XML output."""
        findings = []
        try:
            if not xml_output or "<niktoscan" not in xml_output:
                return findings
            
            root = ET.fromstring(xml_output)
            
            for scan in root.findall(".//scandetails"):
                for item in scan.findall(".//item"):
                    finding = {
                        "id": item.get("id", ""),
                        "osvdb": item.get("osvdb", ""),
                        "method": item.get("method", "GET"),
                        "uri": item.get("uri", ""),
                        "description": item.text.strip() if item.text else "",
                        "severity": "medium"  # Nikto doesn't provide severity
                    }
                    findings.append(finding)
                    
        except ET.ParseError as e:
            logger.error(f"Error parsing Nikto XML: {e}")
        except Exception as e:
            logger.error(f"Error processing Nikto output: {e}")
        
        return findings
    
    @staticmethod
    def execute_dirb_scan(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute DIRB directory brute forcer."""
        try:
            target = args["target"]
            wordlist = args.get("wordlist", "common")
            extensions = args.get("extensions")
            recursive = args.get("recursive", True)
            silent = args.get("silent", True)
            timeout = args.get("timeout", 300)
            
            # Build dirb command
            cmd = ["dirb", target]
            
            # Select wordlist
            wordlist_map = {
                "common": "/usr/share/dirb/wordlists/common.txt",
                "big": "/usr/share/dirb/wordlists/big.txt", 
                "small": "/usr/share/dirb/wordlists/small.txt"
            }
            
            if wordlist in wordlist_map:
                cmd.append(wordlist_map[wordlist])
            
            # Add options
            if extensions:
                cmd.extend(["-X", f".{extensions.replace(',', ',.')}"])
            
            if not recursive:
                cmd.append("-w")
            
            if silent:
                cmd.append("-S")
            
            # Execute command
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                check=False
            )
            duration = time.time() - start_time
            
            # Parse results
            findings = WebSecurityTools._parse_dirb_output(result.stdout)
            
            # Generate summary
            if result.returncode == 0:
                summary = f"DIRB scan completed. Found {len(findings)} directories/files on {target}"
            else:
                summary = f"DIRB scan failed for {target}: {result.stderr.strip()}"
                findings = []
            
            # Store artifact
            artifact_uri = None
            if result.stdout:
                from .artifacts import artifact_manager
                artifact_uri = artifact_manager.save_artifact(
                    server_id=server_id,
                    run_id=f"dirb_{int(time.time())}",
                    kind="dirb_scan",
                    content=result.stdout
                )
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"DIRB scan timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"DIRB execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"DIRB scan failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def _parse_dirb_output(output: str) -> List[Dict[str, Any]]:
        """Parse DIRB text output."""
        findings = []
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                # Look for found directories/files
                if '==> DIRECTORY:' in line or '+ ' in line:
                    if '==> DIRECTORY:' in line:
                        path = line.split('DIRECTORY:')[1].strip()
                        finding_type = "directory"
                    else:
                        # Parse "+ URL (CODE:SIZE)"
                        parts = line.split('(')
                        if len(parts) >= 2:
                            path = parts[0].replace('+', '').strip()
                            status_info = parts[1].replace(')', '')
                            finding_type = "file"
                        else:
                            continue
                    
                    finding = {
                        "path": path,
                        "type": finding_type,
                        "status": "found",
                        "method": "GET"
                    }
                    
                    if 'CODE:' in line:
                        # Extract status code
                        import re
                        code_match = re.search(r'CODE:(\d+)', line)
                        if code_match:
                            finding["status_code"] = int(code_match.group(1))
                    
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error parsing DIRB output: {e}")
        
        return findings

class SSLSecurityTools:
    """SSL/TLS security analysis tools."""
    
    @staticmethod
    def execute_sslyze_scan(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute SSLyze SSL/TLS analyzer."""
        try:
            target = args["target"]
            port = args.get("port", 443)
            sni = args.get("sni")
            timeout = args.get("timeout", 30)
            check_vulnerabilities = args.get("check_vulnerabilities", True)
            check_cipher_suites = args.get("check_cipher_suites", True)
            check_certificate = args.get("check_certificate", True)
            
            # Build sslyze command
            target_spec = f"{target}:{port}"
            cmd = ["sslyze", "--json_out=-", target_spec]
            
            if sni:
                cmd.extend(["--sni", sni])
            
            # Add scan options
            if check_vulnerabilities:
                cmd.extend(["--heartbleed", "--ccs_injection", "--robot"])
            
            if check_cipher_suites:
                cmd.extend(["--tlsv1_2", "--tlsv1_3"])
            
            if check_certificate:
                cmd.append("--certinfo")
            
            # Execute command
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                check=False
            )
            duration = time.time() - start_time
            
            # Parse results
            findings = SSLSecurityTools._parse_sslyze_output(result.stdout)
            
            # Generate summary
            if result.returncode == 0:
                vuln_count = len([f for f in findings if f.get("severity") in ["high", "critical"]])
                summary = f"SSLyze scan completed for {target}:{port}. Found {vuln_count} high/critical issues"
            else:
                summary = f"SSLyze scan failed for {target}:{port}: {result.stderr.strip()}"
                findings = []
            
            # Store artifact
            artifact_uri = None
            if result.stdout:
                from .artifacts import artifact_manager
                artifact_uri = artifact_manager.save_artifact(
                    server_id=server_id,
                    run_id=f"sslyze_{int(time.time())}",
                    kind="sslyze_scan",
                    content=result.stdout
                )
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"SSLyze scan timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"SSLyze execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"SSLyze scan failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def _parse_sslyze_output(json_output: str) -> List[Dict[str, Any]]:
        """Parse SSLyze JSON output."""
        findings = []
        try:
            if not json_output:
                return findings
            
            import json
            data = json.loads(json_output)
            
            for server_scan in data.get("server_scan_results", []):
                server_info = server_scan.get("server_info", {})
                hostname = server_info.get("hostname", "unknown")
                
                # Check vulnerabilities
                scan_commands = server_scan.get("scan_commands_results", {})
                
                # Heartbleed
                heartbleed = scan_commands.get("heartbleed", {})
                if heartbleed.get("is_vulnerable_to_heartbleed"):
                    findings.append({
                        "vulnerability": "heartbleed",
                        "severity": "critical",
                        "description": "Server is vulnerable to Heartbleed (CVE-2014-0160)",
                        "host": hostname
                    })
                
                # CCS Injection
                ccs_injection = scan_commands.get("openssl_ccs_injection", {})
                if ccs_injection.get("is_vulnerable_to_ccs_injection"):
                    findings.append({
                        "vulnerability": "ccs_injection",
                        "severity": "high", 
                        "description": "Server is vulnerable to CCS Injection (CVE-2014-0224)",
                        "host": hostname
                    })
                
                # Certificate information
                cert_info = scan_commands.get("certificate_info", {})
                if cert_info:
                    cert_deployments = cert_info.get("certificate_deployments", [])
                    for deployment in cert_deployments:
                        received_cert = deployment.get("received_certificate_chain", [])
                        if received_cert:
                            cert = received_cert[0]
                            # Check certificate issues
                            if cert.get("not_valid_after"):
                                # Add certificate expiration info
                                findings.append({
                                    "type": "certificate_info",
                                    "severity": "info",
                                    "description": f"Certificate expires: {cert.get('not_valid_after')}",
                                    "host": hostname
                                })
                
        except json.JSONDecodeError:
            logger.error("Failed to parse SSLyze JSON output")
        except Exception as e:
            logger.error(f"Error processing SSLyze output: {e}")
        
        return findings

class NetworkDiscoveryTools:
    """Network discovery and analysis tools."""
    
    @staticmethod
    def execute_masscan(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute Masscan high-speed port scanner."""
        try:
            target = args["target"]
            ports = args.get("ports", "1-1000")
            rate = args.get("rate", 1000)
            timeout = args.get("timeout", 300)
            banners = args.get("banners", False)
            
            # Build masscan command
            cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oX", "-"]
            
            if banners:
                cmd.append("--banners")
            
            # Execute command
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                check=False
            )
            duration = time.time() - start_time
            
            # Parse results
            findings = NetworkDiscoveryTools._parse_masscan_output(result.stdout)
            
            # Generate summary
            if result.returncode == 0:
                summary = f"Masscan completed for {target}. Found {len(findings)} open ports"
            else:
                summary = f"Masscan failed for {target}: {result.stderr.strip()}"
                findings = []
            
            # Store artifact
            artifact_uri = None
            if result.stdout:
                from .artifacts import artifact_manager
                artifact_uri = artifact_manager.save_artifact(
                    server_id=server_id,
                    run_id=f"masscan_{int(time.time())}",
                    kind="masscan_scan",
                    content=result.stdout
                )
            
            return ToolResult(
                rc=result.returncode,
                summary=summary,
                artifact_uri=artifact_uri,
                findings=findings,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"Masscan timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"Masscan execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"Masscan failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def _parse_masscan_output(xml_output: str) -> List[Dict[str, Any]]:
        """Parse Masscan XML output."""
        findings = []
        try:
            if not xml_output or "<nmaprun" not in xml_output:
                return findings
            
            root = ET.fromstring(xml_output)
            
            for host in root.findall("host"):
                # Get host address
                address_elem = host.find("address")
                if address_elem is None:
                    continue
                    
                host_ip = address_elem.get("addr")
                
                # Get ports
                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    
                    # Get port state
                    state_elem = port.find("state")
                    port_state = state_elem.get("state") if state_elem is not None else "unknown"
                    
                    if port_state == "open":
                        finding = {
                            "host": host_ip,
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": port_state
                        }
                        
                        # Get banner if available
                        service_elem = port.find("service")
                        if service_elem is not None:
                            finding["service"] = service_elem.get("name", "")
                            finding["banner"] = service_elem.get("banner", "")
                        
                        findings.append(finding)
                        
        except ET.ParseError as e:
            logger.error(f"Error parsing Masscan XML: {e}")
        except Exception as e:
            logger.error(f"Error processing Masscan output: {e}")
        
        return findings

class MetasploitTools:
    """Metasploit Framework integration for penetration testing."""
    
    # Safe modules that are primarily for reconnaissance/enumeration
    SAFE_MODULES = {
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/ssh/ssh_version",
        "auxiliary/scanner/http/http_version",
        "auxiliary/scanner/ftp/ftp_version",
        "auxiliary/scanner/telnet/telnet_version",
        "auxiliary/scanner/mysql/mysql_version",
        "auxiliary/scanner/mssql/mssql_ping",
        "auxiliary/scanner/oracle/oracle_login",
        "auxiliary/scanner/postgres/postgres_version",
        "auxiliary/scanner/vnc/vnc_none_auth",
        "auxiliary/scanner/rdp/rdp_scanner",
        "auxiliary/scanner/smb/smb_enumshares",
        "auxiliary/scanner/smb/smb_enumusers",
        "auxiliary/scanner/snmp/snmp_enum",
        "auxiliary/scanner/dns/dns_amp",
        "auxiliary/scanner/discovery/arp_sweep",
        "auxiliary/scanner/discovery/udp_sweep",
        "auxiliary/scanner/netbios/nbname"
    }
    
    # Dangerous modules that require explicit authorization
    DANGEROUS_MODULES = {
        "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/multi/handler",
        "exploit/windows/dcerpc/ms03_026_dcom",
        "exploit/linux/samba/is_known_pipename",
        "exploit/unix/webapp/php_include",
        "exploit/windows/browser/ms10_002_aurora",
        "exploit/windows/fileformat/"  # Any file format exploit
    }
    
    @staticmethod
    def execute_exploit(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute Metasploit exploit module with safety checks."""
        try:
            module = args["module"]
            target = args["target"]
            payload = args.get("payload", "generic/shell_reverse_tcp")
            lhost = args.get("lhost", "127.0.0.1")
            lport = args.get("lport", 4444)
            rport = args.get("rport", 445)
            timeout = args.get("timeout", 180)
            check_only = args.get("check_only", True)
            safe_mode = args.get("safe_mode", True)
            options = args.get("options", {})
            
            # Safety checks
            if safe_mode and not MetasploitTools._is_safe_module(module):
                return ToolResult(
                    rc=-1,
                    summary=f"Module {module} is not in safe module list. Set safe_mode=false to override (dangerous!).",
                    duration=0
                )
            
            # Build msfconsole resource script
            resource_commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                f"set RPORT {rport}"
            ]
            
            if not check_only:
                resource_commands.extend([
                    f"set PAYLOAD {payload}",
                    f"set LHOST {lhost}",
                    f"set LPORT {lport}"
                ])
            
            # Add custom options
            for key, value in options.items():
                # Sanitize option key/value
                safe_key = MetasploitTools._sanitize_option(key)
                safe_value = MetasploitTools._sanitize_option(value)
                resource_commands.append(f"set {safe_key} {safe_value}")
            
            # Add the action command
            if check_only:
                resource_commands.append("check")
            else:
                resource_commands.append("exploit -j")  # Run as job
            
            resource_commands.append("exit")
            
            # Create temporary resource file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write('\n'.join(resource_commands))
                resource_file = f.name
            
            try:
                # Execute msfconsole with resource file
                cmd = [
                    "msfconsole",
                    "-q",  # Quiet mode
                    "-r", resource_file,  # Resource file
                    "-o", "/tmp/msf_output.txt"  # Output file
                ]
                
                start_time = time.time()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60,
                    check=False
                )
                duration = time.time() - start_time
                
                # Parse results
                findings = MetasploitTools._parse_msf_output(result.stdout, result.stderr)
                
                # Generate summary
                if result.returncode == 0:
                    if check_only:
                        summary = f"Vulnerability check completed for {target} using {module}"
                    else:
                        summary = f"Exploit execution completed against {target}"
                    
                    if findings:
                        summary += f" - {len(findings)} findings"
                else:
                    summary = f"Metasploit execution failed (exit code: {result.returncode})"
                
                # Save artifact
                artifact_uri = None
                if result.stdout:
                    artifact_uri = save_artifact(
                        server_id=server_id,
                        kind="metasploit_exploit",
                        content=result.stdout
                    )
                
                return ToolResult(
                    rc=result.returncode,
                    summary=summary,
                    artifact_uri=artifact_uri,
                    findings=findings,
                    duration=duration
                )
                
            finally:
                # Clean up temporary file
                import os
                try:
                    os.unlink(resource_file)
                except Exception as e:
                    logger.warning(f"Failed to clean up resource file {resource_file}: {e}")
                    
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"Metasploit exploit timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"Metasploit exploit execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"Metasploit exploit failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def execute_auxiliary(server_id: str, args: Dict[str, Any]) -> ToolResult:
        """Execute Metasploit auxiliary module."""
        try:
            module = args["module"]
            target = args.get("target")
            rhosts = args.get("rhosts", target)
            rport = args.get("rport")
            threads = args.get("threads", 10)
            timeout = args.get("timeout", 300)
            verbose = args.get("verbose", False)
            options = args.get("options", {})
            
            # Build msfconsole resource script
            resource_commands = [
                f"use {module}",
                f"set RHOSTS {rhosts}"
            ]
            
            if rport:
                resource_commands.append(f"set RPORT {rport}")
            
            resource_commands.append(f"set THREADS {threads}")
            
            if verbose:
                resource_commands.append("set VERBOSE true")
            
            # Add custom options
            for key, value in options.items():
                safe_key = MetasploitTools._sanitize_option(key)
                safe_value = MetasploitTools._sanitize_option(value)
                resource_commands.append(f"set {safe_key} {safe_value}")
            
            resource_commands.extend(["run", "exit"])
            
            # Create temporary resource file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write('\n'.join(resource_commands))
                resource_file = f.name
            
            try:
                # Execute msfconsole
                cmd = [
                    "msfconsole",
                    "-q",
                    "-r", resource_file
                ]
                
                start_time = time.time()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60,
                    check=False
                )
                duration = time.time() - start_time
                
                # Parse results
                findings = MetasploitTools._parse_msf_output(result.stdout, result.stderr)
                
                # Generate summary
                if result.returncode == 0:
                    summary = f"Auxiliary scan completed on {rhosts} using {module}"
                    if findings:
                        summary += f" - {len(findings)} findings"
                else:
                    summary = f"Metasploit auxiliary failed (exit code: {result.returncode})"
                
                # Save artifact
                artifact_uri = None
                if result.stdout:
                    artifact_uri = save_artifact(
                        server_id=server_id,
                        kind="metasploit_auxiliary",
                        content=result.stdout
                    )
                
                return ToolResult(
                    rc=result.returncode,
                    summary=summary,
                    artifact_uri=artifact_uri,
                    findings=findings,
                    duration=duration
                )
                
            finally:
                # Clean up
                import os
                try:
                    os.unlink(resource_file)
                except Exception as e:
                    logger.warning(f"Failed to clean up auxiliary resource file {resource_file}: {e}")
                    
        except subprocess.TimeoutExpired:
            return ToolResult(
                rc=-1,
                summary=f"Metasploit auxiliary timed out after {timeout} seconds",
                duration=timeout
            )
        except Exception as e:
            logger.error(f"Metasploit auxiliary execution error: {e}")
            return ToolResult(
                rc=-1,
                summary=f"Metasploit auxiliary failed: {str(e)}",
                duration=0
            )
    
    @staticmethod
    def _is_safe_module(module: str) -> bool:
        """Check if a module is considered safe for automated execution."""
        # Check if it's in the explicit safe list
        if module in MetasploitTools.SAFE_MODULES:
            return True
        
        # Check if it's auxiliary (generally safer)
        if module.startswith("auxiliary/scanner/"):
            return True
        
        # Check if it's explicitly dangerous
        for dangerous in MetasploitTools.DANGEROUS_MODULES:
            if module.startswith(dangerous) or module == dangerous:
                return False
        
        # Conservative default: unknown modules are not safe
        return False
    
    @staticmethod
    def _sanitize_option(value: str) -> str:
        """Sanitize Metasploit option values to prevent injection."""
        # Remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[;&|`$(){}[\]<>]', '', str(value))
        return sanitized[:500]  # Limit length
    
    @staticmethod
    def _parse_msf_output(stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse Metasploit output to extract findings."""
        findings = []
        
        try:
            lines = (stdout + "\n" + stderr).split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Parse common patterns
                if '[+]' in line:  # Success/discovery
                    findings.append({
                        "type": "success",
                        "message": line.replace('[+]', '').strip(),
                        "severity": "info"
                    })
                elif '[!]' in line:  # Warning
                    findings.append({
                        "type": "warning", 
                        "message": line.replace('[!]', '').strip(),
                        "severity": "medium"
                    })
                elif '[-]' in line:  # Error/failure
                    findings.append({
                        "type": "error",
                        "message": line.replace('[-]', '').strip(),
                        "severity": "low"
                    })
                elif 'Vulnerable' in line or 'VULNERABLE' in line:
                    findings.append({
                        "type": "vulnerability",
                        "message": line,
                        "severity": "high"
                    })
                elif 'Session' in line and 'created' in line:
                    findings.append({
                        "type": "session",
                        "message": line,
                        "severity": "critical"
                    })
        
        except Exception as e:
            logger.error(f"Error parsing Metasploit output: {e}")
        
        return findings

# Register new tools with the tool registry
def register_extended_tools():
    """Register Phase 2 extended tools (web, SSL, network, Metasploit)."""

    # ── Web security tools ──────────────────────────────────────────────────
    tool_registry.register_tool(
        name="web.nikto",
        description="Web vulnerability scanner using Nikto — detects XSS, SQLi, misconfigs",
        category="web_security",
        schema_file="web_nikto.json",
        executor=WebSecurityTools.execute_nikto_scan
    )

    tool_registry.register_tool(
        name="web.dirb",
        description="Directory and file brute forcer using DIRB wordlists",
        category="web_security",
        schema_file="web_dirb.json",
        executor=WebSecurityTools.execute_dirb_scan
    )

    # ── SSL security tools ──────────────────────────────────────────────────
    tool_registry.register_tool(
        name="ssl.sslyze",
        description="SSL/TLS configuration analyzer — Heartbleed, POODLE, cipher suites",
        category="ssl_security",
        schema_file="ssl_sslyze.json",
        executor=SSLSecurityTools.execute_sslyze_scan
    )

    # ── Network discovery tools ─────────────────────────────────────────────
    tool_registry.register_tool(
        name="net.masscan",
        description="High-speed network port scanner — scans entire subnets fast",
        category="network_discovery",
        schema_file="net_masscan.json",
        executor=NetworkDiscoveryTools.execute_masscan
    )

    # ── Metasploit tools ────────────────────────────────────────────────────
    tool_registry.register_tool(
        name="metasploit.exploit",
        description="Metasploit exploit module execution with safety controls",
        category="exploitation",
        schema_file="metasploit_exploit.json",
        executor=MetasploitTools.execute_exploit
    )

    tool_registry.register_tool(
        name="metasploit.auxiliary",
        description="Metasploit auxiliary modules for scanning and enumeration",
        category="exploitation",
        schema_file="metasploit_auxiliary.json",
        executor=MetasploitTools.execute_auxiliary
    )

    logger.info("Phase 2 tools registered (web, ssl, masscan, metasploit)")


def register_networking_pack():
    """Register the complete Networking Tools Pack — 20+ tools across 5 categories."""

    # ── Import tool modules ─────────────────────────────────────────────────
    try:
        from mcp_tools.networking import NetworkingTools
        from mcp_tools.enum.tools_enum import EnumTools
        from mcp_tools.vuln.tools_vuln import VulnTools
        from mcp_tools.brute.tools_brute import BruteTools
    except ImportError as e:
        logger.error(f"Failed to import networking pack modules: {e}")
        return

    # ── net.* — Network Analysis ────────────────────────────────────────────
    tool_registry.register_tool(
        name="net.scan_advanced",
        description=(
            "Full nmap scan: service detection (-sV), OS fingerprinting (-O), "
            "default NSE scripts, all ports 1-65535"
        ),
        category="network_analysis",
        schema_file="net_scan_advanced.json",
        executor=NetworkingTools.execute_nmap_advanced
    )

    tool_registry.register_tool(
        name="net.scan_udp",
        description=(
            "UDP port scan targeting common UDP services: DNS(53), DHCP(67/68), "
            "TFTP(69), NTP(123), SNMP(161), Syslog(514), mDNS(5353)"
        ),
        category="network_analysis",
        schema_file="net_scan_udp.json",
        executor=NetworkingTools.execute_nmap_udp
    )

    tool_registry.register_tool(
        name="net.ping_sweep",
        description=(
            "ICMP host discovery sweep — identify all live hosts in a CIDR range "
            "without port scanning (fast recon)"
        ),
        category="network_analysis",
        schema_file="net_ping_sweep.json",
        executor=NetworkingTools.execute_ping_sweep
    )

    tool_registry.register_tool(
        name="net.traceroute",
        description=(
            "Trace network path to target — identify routing hops, "
            "detect firewalls/middleboxes, measure latency per hop"
        ),
        category="network_analysis",
        schema_file="net_traceroute.json",
        executor=NetworkingTools.execute_traceroute
    )

    tool_registry.register_tool(
        name="net.arp_scan",
        description=(
            "Layer 2 ARP scan — discovers all live hosts on the local subnet "
            "by MAC address (cannot be blocked by host firewalls)"
        ),
        category="network_analysis",
        schema_file="net_arp_scan.json",
        executor=NetworkingTools.execute_arp_scan
    )

    tool_registry.register_tool(
        name="net.whois",
        description=(
            "WHOIS lookup for domain or IP — returns registrar, owner, "
            "netblock, country, creation/expiry dates, name servers"
        ),
        category="network_analysis",
        schema_file="net_whois.json",
        executor=NetworkingTools.execute_whois
    )

    tool_registry.register_tool(
        name="net.dns_lookup",
        description=(
            "DNS record enumeration — queries A, AAAA, MX, NS, TXT, CNAME, SOA "
            "records; supports custom nameserver"
        ),
        category="network_analysis",
        schema_file="net_dns_lookup.json",
        executor=NetworkingTools.execute_dns_lookup
    )

    tool_registry.register_tool(
        name="net.dns_zone_transfer",
        description=(
            "DNS zone transfer attempt (AXFR) — if server is misconfigured, "
            "reveals ALL DNS records. Critical finding if successful."
        ),
        category="network_analysis",
        schema_file="net_dns_zone_transfer.json",
        executor=NetworkingTools.execute_dns_zone_transfer
    )

    tool_registry.register_tool(
        name="net.snmp_enum",
        description=(
            "SNMP enumeration using snmpwalk — retrieves system info, "
            "interfaces, running processes, ARP table via community string"
        ),
        category="network_analysis",
        schema_file="net_snmp_enum.json",
        executor=NetworkingTools.execute_snmp_enum
    )

    tool_registry.register_tool(
        name="net.banner_grab",
        description=(
            "TCP service banner grabbing — captures version strings from "
            "SSH, FTP, SMTP, HTTP, databases to fingerprint software versions"
        ),
        category="network_analysis",
        schema_file="net_banner_grab.json",
        executor=NetworkingTools.execute_banner_grab
    )

    # ── enum.* — Service Enumeration ────────────────────────────────────────
    tool_registry.register_tool(
        name="enum.smb",
        description=(
            "SMB/Samba enumeration using enum4linux-ng — discovers shares, "
            "users, groups, password policies, OS info"
        ),
        category="enumeration",
        schema_file="enum_smb.json",
        executor=EnumTools.execute_smb_enum
    )

    tool_registry.register_tool(
        name="enum.ssh",
        description=(
            "SSH server audit using ssh-audit — checks key exchange algorithms, "
            "ciphers, MACs for weak/deprecated options and known CVEs"
        ),
        category="enumeration",
        schema_file="enum_ssh.json",
        executor=EnumTools.execute_ssh_audit
    )

    tool_registry.register_tool(
        name="enum.http_headers",
        description=(
            "HTTP response headers analysis + technology fingerprinting via WhatWeb — "
            "detects web server, frameworks, CMS, security header gaps"
        ),
        category="enumeration",
        schema_file="enum_http_headers.json",
        executor=EnumTools.execute_http_headers
    )

    tool_registry.register_tool(
        name="enum.ftp",
        description=(
            "FTP service enumeration — checks anonymous login, banner grabbing, "
            "BOUNCE attack, SYST info via nmap FTP scripts"
        ),
        category="enumeration",
        schema_file="enum_ftp.json",
        executor=EnumTools.execute_ftp_enum
    )

    tool_registry.register_tool(
        name="enum.smtp",
        description=(
            "SMTP user enumeration via VRFY/EXPN/RCPT — identifies valid email accounts "
            "and checks for open relay, NTLM auth info"
        ),
        category="enumeration",
        schema_file="enum_smtp.json",
        executor=EnumTools.execute_smtp_enum
    )

    tool_registry.register_tool(
        name="enum.ldap",
        description=(
            "LDAP enumeration — checks anonymous bind, queries base DN, "
            "extracts users/groups/OUs from Active Directory or OpenLDAP"
        ),
        category="enumeration",
        schema_file="enum_ldap.json",
        executor=EnumTools.execute_ldap_enum
    )

    tool_registry.register_tool(
        name="enum.rdp",
        description=(
            "RDP service enumeration — checks encryption level, NLA enforcement, "
            "MS12-020 DoS vulnerability via nmap RDP scripts"
        ),
        category="enumeration",
        schema_file="enum_rdp.json",
        executor=EnumTools.execute_rdp_enum
    )

    # ── vuln.* — Vulnerability Scanning ─────────────────────────────────────
    tool_registry.register_tool(
        name="vuln.nmap_scripts",
        description=(
            "nmap NSE vulnerability scan — runs the 'vuln' script category "
            "to detect known CVEs, backdoors, misconfigurations"
        ),
        category="vulnerability",
        schema_file="vuln_nmap_scripts.json",
        executor=VulnTools.execute_nmap_vuln_scripts
    )

    tool_registry.register_tool(
        name="vuln.searchsploit",
        description=(
            "Search Exploit-DB for known exploits — given a product/service name "
            "returns matching public exploits with CVE IDs and severity"
        ),
        category="vulnerability",
        schema_file="vuln_searchsploit.json",
        executor=VulnTools.execute_searchsploit
    )

    tool_registry.register_tool(
        name="web.gobuster",
        description=(
            "Directory/file/DNS brute force using gobuster — discovers hidden paths, "
            "admin panels, backup files, API endpoints"
        ),
        category="web_security",
        schema_file="web_gobuster.json",
        executor=VulnTools.execute_gobuster
    )

    tool_registry.register_tool(
        name="web.sqlmap",
        description=(
            "Automated SQL injection scanner using sqlmap — detects SQLi in GET/POST "
            "parameters, identifies DBMS, extracts data"
        ),
        category="web_security",
        schema_file="web_sqlmap.json",
        executor=VulnTools.execute_sqlmap
    )

    # ── brute.* — Credential Testing ────────────────────────────────────────
    tool_registry.register_tool(
        name="brute.hydra",
        description=(
            "Multi-protocol credential brute force with Hydra — supports SSH, FTP, "
            "HTTP, SMB, RDP, MySQL, PostgreSQL, and 20+ more protocols"
        ),
        category="credential_testing",
        schema_file="brute_hydra.json",
        executor=BruteTools.execute_hydra
    )

    tool_registry.register_tool(
        name="brute.medusa",
        description=(
            "Parallel brute force tool Medusa — high-speed credential testing "
            "alternative to Hydra with modular protocol support"
        ),
        category="credential_testing",
        schema_file="brute_medusa.json",
        executor=BruteTools.execute_medusa
    )

    tool_count = len(tool_registry.tools)
    logger.info(
        f"Networking Pack registered successfully — "
        f"total tools available: {tool_count}"
    )


# Register all tools when module is imported
register_extended_tools()
register_networking_pack()