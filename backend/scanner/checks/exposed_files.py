import re
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult


def _is_html_response(response, content: str) -> bool:
    """Detects whether a response is an HTML page (e.g. SPA fallback, custom 404, or web app shell)."""
    if response and hasattr(response, "headers") and response.headers:
        content_type = response.headers.get("content-type", "").lower()
        if "text/html" in content_type or "application/xhtml+xml" in content_type:
            return True
    lower = content.strip().lower()
    if (
        lower.startswith("<!doctype html")
        or lower.startswith("<html")
        or "<head>" in lower
        or "<body>" in lower
        or "<script" in lower
        or "<meta " in lower
    ):
        return True
    return False


def _validate_env_content(content: str) -> tuple[bool, str]:
    """
    Validates whether the response content is a genuine .env configuration file
    and returns (is_valid, redacted_evidence).
    Secret values are strictly REDACTED and never stored or logged raw.
    """
    if not content or len(content.strip()) < 4:
        return False, ""

    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        return False, ""

    env_pattern = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.*)$')
    valid_keys = []
    redacted_lines = []

    for line in lines:
        m = env_pattern.match(line)
        if m:
            key = line.split("=")[0].strip()
            # Filter out HTML attributes, CSS properties, or JavaScript expressions
            if any(char in key for char in ['<', '>', ';', '{', '}', '"', "'", ' ']):
                continue
            valid_keys.append(key)
            redacted_lines.append(f"{key}=[REDACTED]")

    sensitive_markers = {
        "secret", "password", "passwd", "token", "key", "api", "database",
        "db", "auth", "jwt", "admin", "private", "env", "port", "host",
        "redis", "mail", "aws", "cert", "s3"
    }
    has_sensitive_key = any(any(sm in k.lower() for sm in sensitive_markers) for k in valid_keys)

    # Legitimate .env files have at least 2 distinct env keys, or at least 1 explicitly sensitive key
    if len(valid_keys) >= 2 or (len(valid_keys) >= 1 and has_sensitive_key):
        sample = "\n".join(redacted_lines[:8])
        evidence = (
            f"Validated genuine environment configuration file with {len(valid_keys)} variable(s) "
            f"({', '.join(valid_keys[:5])}{'...' if len(valid_keys) > 5 else ''}). "
            f"Secret values safely redacted:\n{sample}"
        )
        return True, evidence

    return False, ""


def _validate_git_head(content: str) -> tuple[bool, str]:
    """
    Validates whether content is a legitimate Git repository HEAD file:
    either 'ref: refs/heads/<branch>' or a 40-character SHA-1 hex commit hash.
    """
    stripped = content.strip()
    if stripped.startswith("ref: refs/heads/") and len(stripped.splitlines()) <= 2:
        return True, f"Validated legitimate Git repository HEAD referencing branch: {stripped}"
    if re.match(r'^[0-9a-f]{40}$', stripped):
        return True, f"Validated legitimate detached Git repository HEAD with commit hash: {stripped}"
    return False, ""


def _validate_json_config(file_name: str, content: str) -> tuple[bool, str]:
    """Validates legitimate JSON package configuration files."""
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            return False, ""
        if file_name == "package.json":
            if any(k in data for k in ["name", "version", "dependencies", "devDependencies", "scripts", "main"]):
                name = data.get("name", "unnamed")
                ver = data.get("version", "unknown")
                return True, f"Validated legitimate package.json file (package: '{name}' v{ver})."
        elif file_name == "composer.json":
            if any(k in data for k in ["name", "require", "require-dev", "autoload"]):
                name = data.get("name", "unnamed")
                return True, f"Validated legitimate composer.json file (package: '{name}')."
    except Exception:
        pass
    return False, ""


async def check_exposed_files(scanner: SecurityScanner, base_url: str, client: SafeHTTPClient):
    sensitive_files = {
        ".env": "high",
        ".git/HEAD": "high",
        "package.json": "low",
        "composer.json": "low",
        "robots.txt": "info",
        "sitemap.xml": "info"
    }

    for file, severity in sensitive_files.items():
        test_url = urljoin(base_url, file)
        test_case = TestCaseResult(
            category="exposed_files",
            target_endpoint=test_url,
            http_method="GET",
            severity=severity,
            remediation=[f"Restrict access to {file} or remove it from the public web root."],
            owasp="A05:2021-Security Misconfiguration"
        )

        try:
            response = await client.get(test_url)
            if response and response.status_code == 200:
                content = response.text or ""

                # Step 1: Detect HTML / SPA router fallback
                is_html = _is_html_response(response, content)

                is_exposed = False
                matched_evidence = ""

                if is_html and file in (".env", ".git/HEAD", "package.json", "composer.json"):
                    test_case.add_observation(
                        "html_fallback",
                        f"Request to {test_url} returned HTTP 200 with HTML application content. "
                        f"This represents a single-page application (SPA) fallback or custom 404 router, "
                        f"not a legitimate exposed {file} file.",
                        is_suspicious=False,
                        is_strong_evidence=False
                    )
                else:
                    if file == ".env":
                        is_exposed, matched_evidence = _validate_env_content(content)
                    elif file == ".git/HEAD":
                        is_exposed, matched_evidence = _validate_git_head(content)
                    elif file in ("package.json", "composer.json"):
                        is_exposed, matched_evidence = _validate_json_config(file, content)
                    elif file == "robots.txt":
                        if "user-agent:" in content.lower() and not is_html:
                            # Harmless standard discovery file — not a vulnerability
                            test_case.status = "NOT_DETECTED"
                    elif file == "sitemap.xml":
                        if "<urlset" in content.lower() and not is_html:
                            # Harmless standard discovery file — not a vulnerability
                            test_case.status = "NOT_DETECTED"

                    if is_exposed:
                        test_case.add_observation(
                            "content_match",
                            matched_evidence,
                            is_strong_evidence=(severity != "info")
                        )
                    elif test_case.status != "NOT_DETECTED":
                        test_case.add_observation(
                            "content_mismatch",
                            f"File returned HTTP 200 but content failed structure validation for {file}. "
                            f"Response is likely a custom error page or application fallback.",
                            is_suspicious=False,
                            is_strong_evidence=False
                        )

        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error accessing file {file}: {str(e)}"

        if test_case.status != "SCANNER_ERROR":
            test_case.evaluate()
            # Accessible standard harmless files are NOT vulnerabilities
            if severity == "info":
                test_case.status = "NOT_DETECTED"

        # Only confirmed positive findings with verified content are recorded
        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="exposed_files",
                severity=severity if test_case.status != "SCANNER_ERROR" else "info",
                status=test_case.status,
                title=f"Exposed Sensitive File: {file}" if test_case.status != "SCANNER_ERROR" else f"Exposed File Check Error: {file}",
                description=f"Publicly accessible sensitive file '{file}' verified on target.",
                evidence=test_case.evidence,
                impact=f"Exposing {file} can disclose sensitive credentials, internal repository history, or configuration secrets.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=test_url
            )

    # Directory Listing Check
    paths_to_test = [base_url, urljoin(base_url, "images/"), urljoin(base_url, "assets/")]
    for path in paths_to_test:
        test_case = TestCaseResult(
            category="misconfiguration",
            target_endpoint=path,
            http_method="GET",
            severity="medium",
            owasp="A05:2021-Security Misconfiguration"
        )
        try:
            response = await client.get(path)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text or "", "html.parser")
                title = soup.title.string if soup.title and soup.title.string else ""

                if "Index of /" in title or "Directory Listing For" in title:
                    test_case.add_observation(
                        "directory_listing",
                        f"Directory listing verified enabled at {path}. Page title: '{title}'.",
                        is_strong_evidence=True
                    )
                else:
                    test_case.add_observation(
                        "no_listing",
                        f"Page title '{title}' does not indicate directory listing.",
                        is_suspicious=False
                    )
        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error checking directory listing at {path}: {str(e)}"

        if test_case.status != "SCANNER_ERROR":
            test_case.evaluate()

        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="misconfiguration",
                severity="medium" if test_case.status != "SCANNER_ERROR" else "info",
                status=test_case.status,
                title="Directory Listing Enabled",
                description=f"Directory listing is enabled at {path}.",
                evidence=test_case.evidence,
                impact="Attackers can view directory listings, identifying source files, scripts, and sensitive assets.",
                remediation=["Disable directory indexing (Options -Indexes in Apache, autoindex off in Nginx)."],
                owasp=test_case.owasp,
                url=path
            )
