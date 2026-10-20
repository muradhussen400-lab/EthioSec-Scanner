import json
from typing import Dict, Any, List

class RemediationEngine:
    """
    EthioSec Remediation & Security Guidance Engine.
    Takes a confirmed finding and generates a precise remediation package based on evidence.
    """
    
    @staticmethod
    def generate_remediation_package(finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a structured remediation package based on finding category and evidence.
        """
        category = finding.get('type', 'Unknown').lower()
        endpoint = finding.get('url', 'Unknown')
        parameter = finding.get('parameter', 'Unknown')
        evidence = finding.get('evidence', 'No evidence provided')
        
        package = {
            "vulnerability_category": finding.get('type', 'Unknown'),
            "affected_endpoint": endpoint,
            "affected_parameter": parameter,
            "evidence": evidence,
            "root_cause_explanation": "",
            "security_impact": finding.get('impact', ''),
            "recommended_fix": "",
            "secure_code_pattern": "",
            "configuration_guidance": "",
            "verification_checklist": [],
            "retest_plan": "",
            "remediation_status": "REMEDIATION_RECOMMENDED"
        }

        # Populate specifics based on category
        if "sql" in category or "sqli" in category:
            package["root_cause_explanation"] = f"Untrusted input from parameter '{parameter}' at '{endpoint}' is being directly interpolated or concatenated into a database query without parameterization or escaping. This allows an attacker to alter the structure of the SQL query."
            if not package["security_impact"]:
                package["security_impact"] = "Allows attackers to read, modify, or delete sensitive database information, and potentially gain administrative access to the database server."
            package["recommended_fix"] = "Use parameterized queries (prepared statements) or an ORM that automatically parameterizes inputs. Never concatenate user input directly into SQL strings."
            package["secure_code_pattern"] = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,)) # Example in Python/Psycopg2"
            package["configuration_guidance"] = "Ensure the database user has least-privilege access, unable to drop tables or access other databases."
            package["verification_checklist"] = [
                "Verify that all queries using this parameter use prepared statements.",
                "Verify that no string concatenation is used to build SQL queries with this input."
            ]
            package["retest_plan"] = "Re-submit the identified payload via the scanner's retest feature and verify the application safely handles the input as literal data, returning normal validation errors or empty results, rather than executing the payload."

        elif "xss" in category or "cross-site scripting" in category:
            package["root_cause_explanation"] = f"Untrusted input from parameter '{parameter}' is reflected or stored and subsequently rendered in the HTML response without adequate context-aware output encoding. The browser misinterprets the input as executable code."
            if not package["security_impact"]:
                package["security_impact"] = "Allows attackers to execute arbitrary JavaScript in the victim's browser, leading to session hijacking, defacement, or unauthorized actions on behalf of the user."
            package["recommended_fix"] = "Apply context-aware output encoding before rendering the input. Use framework-native escaping mechanisms. Implement a strict Content Security Policy (CSP) as defense-in-depth."
            package["secure_code_pattern"] = "<!-- Example in Jinja2 -->\n<div>{{ user_input | e }}</div>"
            package["configuration_guidance"] = "Implement Content-Security-Policy (CSP) headers restricting script-src to trusted domains and disallowing inline scripts."
            package["verification_checklist"] = [
                "Verify that the input is safely encoded (e.g., `<` becomes `&lt;`).",
                "Verify that no raw input is evaluated in JS contexts like `eval()` or `innerHTML`."
            ]
            package["retest_plan"] = "Re-submit the identified XSS payload via the scanner's retest feature and ensure the payload is safely encoded in the HTTP response, rather than appearing as raw HTML/JS tags."

        elif "access control" in category or "idor" in category or "bola" in category:
            package["root_cause_explanation"] = f"The endpoint '{endpoint}' accepts the identifier '{parameter}' but fails to verify if the currently authenticated user is authorized to access or modify the corresponding resource."
            if not package["security_impact"]:
                package["security_impact"] = "Allows an attacker to view, modify, or delete resources belonging to other users, potentially leading to complete data compromise."
            package["recommended_fix"] = "Implement strict server-side access control checks. Do not rely solely on the client provided ID. Always verify that the requested resource ID belongs to or is authorized for the `user_id` of the current session."
            package["secure_code_pattern"] = "resource = db.query(Resource).filter(Resource.id == requested_id, Resource.owner_id == current_user.id).first()"
            package["configuration_guidance"] = "Ensure authorization logic is applied globally (e.g., via middleware or decorators) rather than relying on developers remembering to add it to each endpoint."
            package["verification_checklist"] = [
                "Verify that user A cannot access user B's resource by manipulating the ID.",
                "Verify that unauthenticated users are correctly rejected."
            ]
            package["retest_plan"] = "Attempt to access the unauthorized resource identifier using a different session token. Verify that a 403 Forbidden or 404 Not Found is returned instead of 200 OK."

        elif "cookie" in category:
            package["root_cause_explanation"] = f"The cookie '{parameter}' at '{endpoint}' is missing secure attributes or is misconfigured, making it susceptible to interception or unintended cross-site sending."
            if not package["security_impact"]:
                package["security_impact"] = "May allow attackers to steal session tokens via network eavesdropping (if missing Secure) or cross-site scripting (if missing HttpOnly), or perform CSRF (if missing SameSite)."
            package["recommended_fix"] = "Configure the Set-Cookie header to include the 'Secure', 'HttpOnly', and appropriate 'SameSite' attributes based on the cookie's purpose."
            package["secure_code_pattern"] = "Set-Cookie: session_id=123; Secure; HttpOnly; SameSite=Strict"
            package["configuration_guidance"] = "Set default cookie policies in your web framework (e.g., SESSION_COOKIE_SECURE = True in Django or Flask)."
            package["verification_checklist"] = [
                "Verify the 'Secure' flag is present on all sensitive cookies.",
                "Verify the 'HttpOnly' flag is present to prevent JS access.",
                "Verify the 'SameSite' flag is configured."
            ]
            package["retest_plan"] = "Re-scan the endpoint and verify the 'Set-Cookie' header contains all recommended attributes in the response."

        elif "cors" in category:
            package["root_cause_explanation"] = f"The endpoint '{endpoint}' is returning excessively permissive CORS headers (e.g., Access-Control-Allow-Origin: *) or improperly trusting the Origin header dynamically, especially with credentials allowed."
            if not package["security_impact"]:
                package["security_impact"] = "Allows arbitrary malicious websites to read the responses from the vulnerable application, potentially stealing sensitive data or performing actions on behalf of the user."
            package["recommended_fix"] = "Restrict the 'Access-Control-Allow-Origin' header to an explicit whitelist of trusted domains. Do not use a wildcard (*) if 'Access-Control-Allow-Credentials' is true."
            package["secure_code_pattern"] = "Access-Control-Allow-Origin: https://trusted-domain.com\nAccess-Control-Allow-Credentials: true"
            package["configuration_guidance"] = "Configure your CORS middleware/plugin to explicitly list allowed origins rather than dynamically reflecting the incoming Origin header."
            package["verification_checklist"] = [
                "Verify that requests with untrusted origins do not receive permissive CORS headers.",
                "Verify that wildcards are not used alongside allowed credentials."
            ]
            package["retest_plan"] = "Send a request with an untrusted `Origin` header and verify that the response does not echo the untrusted origin in the `Access-Control-Allow-Origin` header."

        elif "disclosure" in category or "exposure" in category or "exposed" in category:
            package["root_cause_explanation"] = f"The endpoint or file at '{endpoint}' is publicly accessible and contains sensitive information or debugging data that should not be exposed."
            if not package["security_impact"]:
                package["security_impact"] = "Provides attackers with critical system details, credentials, or code logic, greatly facilitating further targeted attacks."
            package["recommended_fix"] = "Remove the sensitive data from the response, disable debug mode in production, or restrict access to the file/endpoint using authentication."
            package["secure_code_pattern"] = "DEBUG = False # Ensure debug mode is disabled in production environments."
            package["configuration_guidance"] = "Configure your web server (e.g., Nginx/Apache) to deny access to specific extensions like .env, .git, or backup files."
            package["verification_checklist"] = [
                "Verify that the endpoint returns a generic error or requires authentication.",
                "Verify that stack traces and system paths are removed from error responses."
            ]
            package["retest_plan"] = "Request the URL again and verify that it returns a 404 Not Found or 403 Forbidden without disclosing any sensitive configuration or data."
            
        else:
            package["root_cause_explanation"] = "The scanner identified anomalous or vulnerable behavior at the specified endpoint based on the provided evidence."
            if not package["security_impact"]:
                package["security_impact"] = "Varies depending on the specific vulnerability context."
            package["recommended_fix"] = "Review the evidence provided and ensure that all untrusted input is properly validated, sanitized, and authorized."
            package["verification_checklist"] = ["Verify that the anomalous behavior is no longer present after applying a fix."]
            package["retest_plan"] = "Run the scanner again against this endpoint to confirm the vulnerability is no longer detected."

        return package

    @staticmethod
    def generate_remediation_report(finding: Dict[str, Any]) -> str:
        """
        Generates a markdown formatted remediation report.
        """
        package = RemediationEngine.generate_remediation_package(finding)
        
        report = f"""# Remediation Report: {package['vulnerability_category']}

## 1. Finding Overview
- **Vulnerability Category:** {package['vulnerability_category']}
- **Affected Endpoint:** `{package['affected_endpoint']}`
- **Affected Parameter:** `{package['affected_parameter']}`
- **Remediation Status:** `{package['remediation_status']}`

## 2. Evidence Collected
```
{package['evidence']}
```

## 3. Root Cause Analysis
{package['root_cause_explanation']}

## 4. Security Impact
{package['security_impact']}

## 5. Recommended Fix
{package['recommended_fix']}

### Secure Code Pattern / Configuration Example
```
{package['secure_code_pattern']}
```

### Configuration Guidance
{package['configuration_guidance']}

## 6. Verification & Retest Plan
**Developer Checklist:**
"""
        for item in package['verification_checklist']:
            report += f"- [ ] {item}\n"
            
        report += f"\n**Retest Requirement:**\n{package['retest_plan']}\n"
        
        return report
