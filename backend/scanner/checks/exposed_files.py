from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urljoin
from bs4 import BeautifulSoup

async def check_exposed_files(scanner: SecurityScanner, base_url: str, client: SafeHTTPClient):
    # Files to check
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
        try:
            response = await client.get(test_url)
            
            if response.status_code == 200:
                is_exposed = False
                content = response.text
                
                if file == ".env" and ("=" in content and len(content.splitlines()) > 1):
                    is_exposed = True
                elif file == ".git/HEAD" and "ref:" in content:
                    is_exposed = True
                elif file in ["package.json", "composer.json"] and "{" in content and "}" in content:
                    is_exposed = True
                elif file == "robots.txt" and "user-agent:" in content.lower():
                    is_exposed = True
                elif file == "sitemap.xml" and "<urlset" in content.lower():
                    is_exposed = True
                    
                if is_exposed:
                    status = "open" if severity != "info" else "passed"
                    title = f"Exposed Sensitive File: {file}" if severity != "info" else f"File Found: {file}"
                    
                    scanner._add_finding(
                        f_type="exposed_files",
                        severity=severity,
                        status=status,
                        title=title,
                        description=f"The file '{file}' is publicly accessible.",
                        evidence=f"Request to {test_url} returned HTTP 200. Content snippet: {content[:50]}...",
                        impact=f"Exposing {file} can lead to information disclosure.",
                        remediation=[f"Restrict access to {file} or remove it from the web root if it contains sensitive data."],
                        owasp="A02:2025",
                        url=test_url
                    )
        except Exception:
            pass

    # Basic Directory Listing Check
    paths_to_test = [base_url, urljoin(base_url, "images/"), urljoin(base_url, "assets/")]
    for path in paths_to_test:
        try:
            response = await client.get(path)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string if soup.title else ""
                
                if "Index of /" in title or "Directory Listing For" in title:
                    scanner._add_finding(
                        f_type="misconfiguration",
                        severity="medium",
                        status="open",
                        title="Directory Listing Enabled",
                        description=f"Directory listing is enabled at {path}.",
                        evidence=f"Title of the page was '{title}'",
                        impact="Attackers can view all files in a directory, potentially finding sensitive files or source code.",
                        remediation=["Disable directory listing in the web server configuration."],
                        owasp="A02:2025",
                        url=path
                    )
        except Exception:
            pass # Ignore request errors for these passive tests
