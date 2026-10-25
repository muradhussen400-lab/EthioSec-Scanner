"""
Authoritative Module Registry for EthioSecScan.
Defines canonical security modules, metadata, and selection resolution logic.
"""

from typing import Dict, Any, List

CANONICAL_MODULES: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "id": "sqli",
        "name": "SQL Injection",
        "description": "Checks for in-band, error-based, and boolean injection vulnerabilities",
        "owasp": "A03:2021-Injection",
        "type": "active",
        "aliases": []
    },
    "xss": {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Tests reflected, stored, and DOM-based script injection vectors",
        "owasp": "A03:2021-Injection",
        "type": "active",
        "aliases": []
    },
    "headers": {
        "id": "headers",
        "name": "Security Headers",
        "description": "Audits CSP, HSTS, X-Frame-Options, and Referrer policies",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    },
    "cookies": {
        "id": "cookies",
        "name": "Cookie Security",
        "description": "Audits Secure, HttpOnly, and SameSite flags across sessions",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    },
    "cors": {
        "id": "cors",
        "name": "CORS Policy",
        "description": "Detects overly permissive origins, wildcard ACLs, and null reflections",
        "owasp": "A01:2021-Broken Access Control",
        "type": "passive",
        "aliases": []
    },
    "https": {
        "id": "https",
        "name": "SSL / TLS Configuration",
        "description": "Verifies TLS versions, cipher suites, certificate chains, and HTTPS redirects",
        "owasp": "A02:2021-Cryptographic Failures",
        "type": "passive",
        "aliases": ["tls", "ssl"]
    },
    "auth": {
        "id": "auth",
        "name": "Authentication Security",
        "description": "Tests credential transmission, form security, and session management",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "type": "active",
        "aliases": []
    },
    "access_control": {
        "id": "access_control",
        "name": "Broken Access Control",
        "description": "Evaluates IDOR, privilege boundaries, and authorization contexts",
        "owasp": "A01:2021-Broken Access Control",
        "type": "active",
        "aliases": []
    },
    "exposed_files": {
        "id": "exposed_files",
        "name": "Exposed Sensitive Files",
        "description": "Finds .env, .git, configuration backups, and private source leaks",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    },
    "http_methods": {
        "id": "http_methods",
        "name": "Dangerous HTTP Methods",
        "description": "Detects PUT, DELETE, TRACE, and arbitrary method overrides",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    },
    "info_disclosure": {
        "id": "info_disclosure",
        "name": "Information Disclosure",
        "description": "Identifies server banner leaks, stack traces, and debug artifacts",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    },
    "misconfig": {
        "id": "misconfig",
        "name": "Security Misconfiguration",
        "description": "Audits server configuration, default files, and headers",
        "owasp": "A05:2021-Security Misconfiguration",
        "type": "passive",
        "aliases": []
    }
}

CANONICAL_MODULE_KEYS: List[str] = list(CANONICAL_MODULES.keys())


def resolve_module_selection(raw_modules: Any) -> Dict[str, bool]:
    """
    Given the raw modules dictionary from a scan request, returns an explicit
    dictionary mapping every canonical module key to True or False.
    Enforces strict isolation: unselected modules are never executed accidentally.
    """
    result: Dict[str, bool] = {k: False for k in CANONICAL_MODULE_KEYS}
    
    if not isinstance(raw_modules, dict) or not raw_modules:
        # Default fallback if empty: return all False (user must select modules)
        return result
        
    # Check if 'all' was explicitly enabled
    if raw_modules.get("all") is True:
        return {k: True for k in CANONICAL_MODULE_KEYS}
        
    for k, is_enabled in raw_modules.items():
        if not is_enabled:
            continue
        norm_k = k.lower().strip()
        if norm_k in result:
            result[norm_k] = True
        elif norm_k in ("ssl", "tls"):
            result["https"] = True
            
    # If misconfig was explicitly requested on its own, enable passive misconfiguration audits
    # unless specific checks were already provided
    if raw_modules.get("misconfig") is True:
        result["misconfig"] = True
        # If user explicitly specified any sub-modules (e.g. headers, cookies), respect that
        # otherwise enable core misconfig checks
        has_sub_specified = any(
            raw_modules.get(sub) is not None 
            for sub in ("headers", "cookies", "exposed_files", "http_methods", "info_disclosure", "cors")
        )
        if not has_sub_specified:
            result["headers"] = True
            result["cookies"] = True
            result["exposed_files"] = True
            result["http_methods"] = True
            result["info_disclosure"] = True
            
    return result
