"""Networking tools package for DARK MATER MCP Server."""
from .tools_networking import (
    execute_nmap_advanced,
    execute_nmap_udp,
    execute_ping_sweep,
    execute_traceroute,
    execute_arp_scan,
    execute_whois,
    execute_dns_lookup,
    execute_dns_zone_transfer,
    execute_snmp_enum,
    execute_banner_grab,
)

# Convenience class wrapper
class NetworkingTools:
    execute_nmap_advanced = staticmethod(execute_nmap_advanced)
    execute_nmap_udp = staticmethod(execute_nmap_udp)
    execute_ping_sweep = staticmethod(execute_ping_sweep)
    execute_traceroute = staticmethod(execute_traceroute)
    execute_arp_scan = staticmethod(execute_arp_scan)
    execute_whois = staticmethod(execute_whois)
    execute_dns_lookup = staticmethod(execute_dns_lookup)
    execute_dns_zone_transfer = staticmethod(execute_dns_zone_transfer)
    execute_snmp_enum = staticmethod(execute_snmp_enum)
    execute_banner_grab = staticmethod(execute_banner_grab)

__all__ = ["NetworkingTools"]

