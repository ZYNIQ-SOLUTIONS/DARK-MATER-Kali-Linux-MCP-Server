"""
Scope validation and guardrails module for MCP Kali Server.
Handles CIDR validation, hostname resolution, and destructive operation detection.
"""

import json
import socket
import ipaddress
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Configuration path - handle both Windows and Linux
if os.environ.get("MCP_TEST_CONFIG_DIR"):
    SCOPE_CONFIG_FILE = Path(os.environ["MCP_TEST_CONFIG_DIR"]) / "scope.json"
elif os.name == 'nt':  # Windows
    SCOPE_CONFIG_FILE = Path.home() / ".mcp-kali" / "scope.json"
else:  # Linux/Unix
    SCOPE_CONFIG_FILE = Path("/etc/mcp-kali/scope.json")

class ScopeConfig(BaseModel):
    """Scope configuration model."""
    allowed_cidrs: List[str] = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    allow_destructive: bool = False
    
    class Config:
        extra = "allow"  # Allow additional fields for future extensions

def load_scope_config() -> ScopeConfig:
    """
    Load scope configuration from disk.
    
    Returns:
        ScopeConfig with current settings or defaults
    """
    try:
        if not SCOPE_CONFIG_FILE.exists():
            logger.info(f"Scope config file {SCOPE_CONFIG_FILE} not found, using defaults")
            return ScopeConfig()
            
        with open(SCOPE_CONFIG_FILE, 'r') as f:
            data = json.load(f)
            
        config = ScopeConfig(**data)
        logger.debug(f"Loaded scope config: {len(config.allowed_cidrs)} CIDRs, destructive={config.allow_destructive}")
        return config
        
    except Exception as e:
        logger.error(f"Error loading scope config, using defaults: {e}")
        return ScopeConfig()

def save_scope_config(config: ScopeConfig) -> bool:
    """
    Save scope configuration to disk.
    
    Args:
        config: Scope configuration to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        SCOPE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        with open(SCOPE_CONFIG_FILE, 'w') as f:
            json.dump(config.model_dump(), f, indent=2)
            
        # Secure the file permissions
        SCOPE_CONFIG_FILE.chmod(0o644)
        
        logger.info(f"Scope configuration saved to {SCOPE_CONFIG_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving scope config: {e}")
        return False

def resolve_hostname_to_ip(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address as string, or None if resolution fails
    """
    try:
        # Try to resolve hostname
        ip = socket.gethostbyname(hostname)
        logger.debug(f"Resolved {hostname} to {ip}")
        return ip
    except socket.gaierror as e:
        logger.debug(f"Failed to resolve hostname {hostname}: {e}")
        return None

def parse_target(target: str) -> Optional[ipaddress.IPv4Address]:
    """
    Parse target string into IP address, resolving hostnames if needed.
    
    Args:
        target: Target IP address or hostname
        
    Returns:
        IPv4Address object or None if parsing fails
    """
    try:
        # First try to parse as IP address
        return ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError:
        # Try to resolve as hostname
        ip_str = resolve_hostname_to_ip(target)
        if ip_str:
            try:
                return ipaddress.IPv4Address(ip_str)
            except ipaddress.AddressValueError as e:
                logger.warning(f"Failed to parse resolved IP address string '{ip_str}': {e}")
        
        logger.warning(f"Could not parse target: {target}")
        return None

def ip_in_cidrs(ip: ipaddress.IPv4Address, cidrs: List[str]) -> bool:
    """
    Check if IP address is within any of the allowed CIDR ranges.
    
    Args:
        ip: IP address to check
        cidrs: List of CIDR ranges
        
    Returns:
        True if IP is in any CIDR range, False otherwise
    """
    try:
        for cidr_str in cidrs:
            try:
                cidr = ipaddress.IPv4Network(cidr_str, strict=False)
                if ip in cidr:
                    logger.debug(f"IP {ip} matches CIDR {cidr}")
                    return True
            except ipaddress.AddressValueError as e:
                logger.warning(f"Invalid CIDR in config: {cidr_str} - {e}")
                continue
                
        logger.debug(f"IP {ip} not in any allowed CIDR")
        return False
        
    except Exception as e:
        logger.error(f"Error checking IP against CIDRs: {e}")
        return False

def in_scope(target: str, custom_cidrs: Optional[List[str]] = None) -> bool:
    """
    Check if target is within allowed scope.
    
    Args:
        target: Target IP address, hostname, or CIDR range
        custom_cidrs: Optional list of tenant-specific CIDR ranges overriding server defaults
        
    Returns:
        True if target is in scope, False otherwise
    """
    try:
        if custom_cidrs is not None:
            allowed_cidrs = custom_cidrs
        else:
            config = load_scope_config()
            allowed_cidrs = config.allowed_cidrs
        
        # Handle CIDR ranges in target
        if '/' in target:
            try:
                target_network = ipaddress.IPv4Network(target, strict=False)
                # Check if the entire target network is within allowed scope
                for cidr_str in allowed_cidrs:
                    try:
                        allowed_network = ipaddress.IPv4Network(cidr_str, strict=False)
                        if target_network.subnet_of(allowed_network):
                            logger.debug(f"Target network {target} is within allowed network {cidr_str}")
                            return True
                    except ipaddress.AddressValueError:
                        continue
                        
                logger.warning(f"Target network {target} is not within any allowed CIDR")
                return False
            except ipaddress.AddressValueError:
                logger.warning(f"Invalid target network format: {target}")
                return False
        
        # Handle single IP or hostname
        ip = parse_target(target)
        if not ip:
            logger.warning(f"Could not resolve target to IP: {target}")
            return False
            
        # Check if IP is in private ranges (additional safety)
        if not ip.is_private and not ip.is_loopback:
            logger.warning(f"Target {target} ({ip}) is not in private IP space")
            return False
            
        # Check against configured CIDRs
        return ip_in_cidrs(ip, allowed_cidrs)
        
    except Exception as e:
        logger.error(f"Error checking scope for target {target}: {e}")
        return False

def is_destructive(tool_name: str, args: Dict[str, Any]) -> bool:
    """
    Determine if a tool execution would be destructive.
    
    Args:
        tool_name: Name of the tool being executed
        args: Tool arguments
        
    Returns:
        True if operation is potentially destructive, False otherwise
    """
    try:
        # Define destructive patterns by tool
        destructive_patterns = {
            'net.scan_basic': {
                # Aggressive scan types
                'scan_types': ['-sS', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX'],
                # Fast scans are generally less destructive
                'non_destructive_if_fast': True,
            },
            'web.scan': {
                # SQL injection testing, admin panel detection, etc.
                'always_destructive': True,
            },
            'exploit': {
                # Any exploit tool is inherently destructive
                'always_destructive': True,
            },
            'bruteforce': {
                # Password attacks are destructive
                'always_destructive': True,
            },
            'metasploit.exploit': {
                # Metasploit exploits are destructive unless check_only=True
                'check_destructive_args': ['check_only'],
                'safe_if_check_only': True,
            },
            'metasploit.auxiliary': {
                # Most auxiliary modules are safe, but some can be destructive
                'destructive_modules': [
                    'auxiliary/dos/',  # Denial of service modules
                    'auxiliary/admin/',  # Administrative modules
                    'auxiliary/scanner/smb/smb_login',  # Brute force
                    'auxiliary/scanner/ssh/ssh_login',  # Brute force
                    'auxiliary/scanner/ftp/ftp_login',  # Brute force
                    'auxiliary/scanner/telnet/telnet_login',  # Brute force
                    'auxiliary/scanner/mysql/mysql_login',  # Brute force
                    'auxiliary/scanner/mssql/mssql_login',  # Brute force
                    'auxiliary/gather/',  # Information gathering (potentially invasive)
                ],
                'safe_modules': [
                    'auxiliary/scanner/smb/smb_version',
                    'auxiliary/scanner/ssh/ssh_version',
                    'auxiliary/scanner/http/http_version',
                    'auxiliary/scanner/ftp/ftp_version',
                    'auxiliary/scanner/discovery/',
                ]
            }
        }
        
        # Check if tool is inherently destructive
        if tool_name in destructive_patterns:
            pattern = destructive_patterns[tool_name]
            
            if pattern.get('always_destructive', False):
                logger.debug(f"Tool {tool_name} is always destructive")
                return True
                
            # Check scan types for network tools
            if 'scan_types' in pattern:
                scan_type = args.get('scan_type', '')
                additional_args = args.get('additional_args', '')
                
                # Check if using aggressive scan types
                for destructive_scan in pattern['scan_types']:
                    if destructive_scan in scan_type or destructive_scan in additional_args:
                        # Check if fast mode mitigates destructiveness
                        if pattern.get('non_destructive_if_fast') and args.get('fast', False):
                            logger.debug(f"Tool {tool_name} using {destructive_scan} but fast mode enabled")
                            return False
                        logger.debug(f"Tool {tool_name} using destructive scan type: {destructive_scan}")
                        return True
            
            # Metasploit exploit specific checks
            if tool_name == 'metasploit.exploit':
                # If check_only is True, it's not destructive
                if args.get('check_only', True):
                    logger.debug(f"Metasploit exploit in check-only mode, not destructive")
                    return False
                else:
                    logger.debug(f"Metasploit exploit with execution enabled, destructive")
                    return True
            
            # Metasploit auxiliary specific checks
            if tool_name == 'metasploit.auxiliary':
                module = args.get('module', '')
                
                # Check if module is explicitly safe
                for safe_module in pattern.get('safe_modules', []):
                    if module.startswith(safe_module) or module == safe_module:
                        logger.debug(f"Metasploit auxiliary module {module} is in safe list")
                        return False
                
                # Check if module is explicitly destructive
                for destructive_module in pattern.get('destructive_modules', []):
                    if module.startswith(destructive_module) or module == destructive_module:
                        logger.debug(f"Metasploit auxiliary module {module} is destructive")
                        return True
                
                # Default: auxiliary modules are generally safe unless proven otherwise
                logger.debug(f"Metasploit auxiliary module {module} assumed safe")
                return False
        
        # Additional heuristics
        # Check for timing attacks or aggressive timing
        timing_args = args.get('additional_args', '')
        if any(timing in timing_args for timing in ['-T5', '-T4', '--max-rate']):
            if not args.get('fast', False):  # Fast scans with aggressive timing are usually OK
                logger.debug(f"Tool {tool_name} using aggressive timing")
                return True
                
        # Check for vulnerability scanning keywords
        vuln_keywords = ['vuln', 'exploit', 'attack', 'intrusive', 'dos', 'flood']
        for keyword in vuln_keywords:
            if keyword in str(args.get('additional_args', '')).lower():
                logger.debug(f"Tool {tool_name} has vulnerability keyword: {keyword}")
                return True
        
        logger.debug(f"Tool {tool_name} determined to be non-destructive")
        return False
        
    except Exception as e:
        logger.error(f"Error checking destructiveness for {tool_name}: {e}")
        # Err on the side of caution
        return True

def validate_scope_and_destructiveness(tool_name: str, args: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate both scope and destructiveness for a tool execution.
    
    Args:
        tool_name: Name of the tool
        args: Tool arguments
        
    Returns:
        Tuple of (is_allowed, error_message)
    """
    try:
        # Check scope first
        target = args.get('target', '')
        if target and not in_scope(target):
            return False, f"Target {target} is out of allowed scope"
            
        # Check destructiveness
        if is_destructive(tool_name, args):
            config = load_scope_config()
            if not config.allow_destructive:
                return False, f"Tool {tool_name} is potentially destructive and destructive operations are disabled"
                
        return True, None
        
    except Exception as e:
        logger.error(f"Error validating scope and destructiveness: {e}")
        return False, f"Validation error: {e}"

def get_scope_info() -> Dict[str, Any]:
    """
    Get current scope configuration information.
    
    Returns:
        Dictionary with scope configuration details
    """
    try:
        config = load_scope_config()
        return {
            "allowed_cidrs": config.allowed_cidrs,
            "allow_destructive": config.allow_destructive,
            "config_file": str(SCOPE_CONFIG_FILE),
            "config_exists": SCOPE_CONFIG_FILE.exists()
        }
    except Exception as e:
        logger.error(f"Error getting scope info: {e}")
        return {"error": str(e)}

# Create default scope configuration if it doesn't exist
def ensure_scope_config():
    """Ensure scope configuration file exists with defaults."""
    if not SCOPE_CONFIG_FILE.exists():
        default_config = ScopeConfig()
        save_scope_config(default_config)
        logger.info("Created default scope configuration")