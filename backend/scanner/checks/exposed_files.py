from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from scanner.test_case import TestCaseResult

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
            remediation=[f"Restrict access to {file} or remove it from the web root if it contains sensitive data."],
            owasp="A05:2021-Security Misconfiguration"
        )
        
        try:
            response = await client.get(test_url)
            if response and response.status_code == 200:
                content = response.text
                test_case.add_observation("http_200", f"Request to {test_url} returned HTTP 200.", is_suspicious=True)
                
                is_exposed = False
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
                    test_case.add_observation("content_match", f"Content validates this is a legitimate {file} file.", is_strong_evidence=(severity != "info"))
                else:
                    test_case.add_observation("false_positive", f"File returned HTTP 200 but content doesn't match expected format. Likely custom 404.", is_suspicious=False)
                    
        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error accessing file: {str(e)}"
            
        if test_case.status != "SCANNER_ERROR":
            test_case.evaluate()
            
            # Downgrade info level (robots.txt) to NOT_DETECTED so they aren't marked as vulnerabilities
            # unless the user wants them? Wait, the prompt said:
            # "Do not report robots.txt merely because it exists."
            # "Accessible + harmless -> NOT_DETECTED"
            if severity == "info":
                test_case.status = "NOT_DETECTED"

        if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="exposed_files",
                severity=severity if test_case.status != "SCANNER_ERROR" else "info",
                status=test_case.status,
                title=f"Exposed File: {file}" if test_case.status != "SCANNER_ERROR" else f"Exposed File Check Error: {file}",
                description=f"Testing accessibility of '{file}'.",
                evidence=test_case.evidence,
                impact=f"Exposing {file} can lead to information disclosure.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=test_url
            )

    # Basic Directory Listing Check
    paths_to_test = [base_url, urljoin(base_url, "images/"), urljoin(base_url, "assets/")]
    for path in paths_to_test:
        test_case = TestCaseResult(category="misconfiguration", target_endpoint=path, http_method="GET", owasp="A05:2021-Security Misconfiguration")
        try:
            response = await client.get(path)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string if soup.title else ""
                
                if "Index of /" in title or "Directory Listing For" in title:
                    test_case.add_observation("directory_listing", f"Title of the page was '{title}'", is_strong_evidence=True)
                else:
                    test_case.add_observation("no_listing", f"Page title '{title}' does not indicate directory listing.", is_suspicious=False)
        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error checking directory listing: {str(e)}"
            
        if test_case.status != "SCANNER_ERROR":
            test_case.evaluate()
            
        if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="misconfiguration",
                severity="medium" if test_case.status != "SCANNER_ERROR" else "info",
                status=test_case.status,
                title="Directory Listing Enabled",
                description=f"Directory listing is enabled at {path}.",
                evidence=test_case.evidence,
                impact="Attackers can view all files in a directory, potentially finding sensitive files or source code.",
                remediation=["Disable directory listing in the web server configuration."],
                owasp=test_case.owasp,
                url=path
            )
