import ipaddress
import socket
from urllib.parse import urlparse

class UnsafeTargetError(Exception):
    pass

def is_safe_url(url: str) -> bool:
    """
    Validates a URL to prevent SSRF by resolving its hostname and checking against safe IP ranges.
    Returns True if safe, raises UnsafeTargetError if unsafe.
    """
    parsed = urlparse(url)
    
    if parsed.scheme not in ["http", "https"]:
        raise UnsafeTargetError(f"Unsupported scheme: {parsed.scheme}")
        
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeTargetError("Invalid URL: missing hostname")
        
    try:
        # Resolve hostname to IP address
        # Note: socket.gethostbyname only returns IPv4 in most cases, 
        # getaddrinfo is more robust for both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None)
        ips = [info[4][0] for info in addr_info]
    except socket.gaierror:
        raise UnsafeTargetError(f"Could not resolve hostname: {hostname}")
        
    import os
    allow_local = os.getenv("ALLOW_LOCAL_TARGETS", "false").lower() == "true"
    
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue # should not happen from getaddrinfo
            
        if not allow_local:
            if ip.is_private:
                raise UnsafeTargetError(f"Target resolves to a private IP: {ip_str}")
            if ip.is_loopback:
                raise UnsafeTargetError(f"Target resolves to a loopback IP: {ip_str}")
            if ip.is_link_local:
                raise UnsafeTargetError(f"Target resolves to a link-local IP: {ip_str}")
            if ip.is_multicast:
                raise UnsafeTargetError(f"Target resolves to a multicast IP: {ip_str}")
            if ip.is_reserved:
                raise UnsafeTargetError(f"Target resolves to a reserved IP: {ip_str}")
            
    return True
