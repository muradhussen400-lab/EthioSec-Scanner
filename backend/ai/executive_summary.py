"""
EthioSec Executive Summary & 5-Category Posture Engine.
Provides evidence-grounded, structured AI executive summaries and consistent
5-category aggregation matching the exact EthioSec security model.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ethiosec.ai.executive_summary")

# ==============================================================================
# 1. FIVE-CATEGORY AGGREGATION & MAPPING RULES
# ==============================================================================
# The 5 user-facing categories are:
#   1. HIGH
#   2. MEDIUM
#   3. LOW
#   4. NOT DETECTED
#   5. SCANNER ERROR
#
# Technical distinction:
#   HIGH, MEDIUM, LOW are finding severity levels.
#   NOT DETECTED and SCANNER ERROR are check outcomes.
#   CONFIRMED and INCONCLUSIVE are internal evidence/detection statuses.
# ==============================================================================

def map_finding_to_category(finding: Any) -> str:
    """
    Maps an individual finding to one of the 5 top-level categories:
    'HIGH', 'MEDIUM', 'LOW', 'NOT_DETECTED', 'SCANNER_ERROR', or 'INCONCLUSIVE'.
    Follows strict evidence-driven mapping rules.
    """
    status = (getattr(finding, "status", None) or "").upper()
    severity = (getattr(finding, "severity", None) or "low").lower()

    if status == "SCANNER_ERROR":
        return "SCANNER_ERROR"
    if status == "INCONCLUSIVE":
        return "INCONCLUSIVE"
    if status == "NOT_DETECTED" and severity not in ("critical", "high", "medium"):
        return "NOT_DETECTED"

    # Confirmed finding: prioritize explicit severity
    if severity in ("critical", "high") or status in ("HIGH", "CRITICAL"):
        return "HIGH"
    if severity == "medium" or status == "MEDIUM":
        return "MEDIUM"
    if severity in ("low", "info") or status == "LOW":
        return "LOW"

    return "LOW"


def aggregate_finding_counts(findings: List[Any], scan: Optional[Any] = None) -> Dict[str, int]:
    """
    Calculates verified counts for all top-level categories with strict rules:
    - Deduplicates findings by (type, url, parameter, title) so duplicates do not inflate dashboard counts.
    - Confirmed HIGH severity -> high
    - Confirmed MEDIUM severity -> medium
    - Confirmed LOW severity -> low
    - Completed negative checks -> not_detected
    - Failed checks -> scanner_error
    - Inconclusive checks -> recorded in 'inconclusive'
    - Confirmed findings -> confirmed
    - Potential findings -> potential
    - Blocked checks -> blocked
    - Skipped checks -> skipped
    - Not tested checks -> not_tested
    - Total confirmed vulnerabilities = high + medium + low.
    """
    c = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "not_detected": 0,
        "scanner_error": 0,
        "inconclusive": 0,
        "critical": 0,  # Maintained for backward compatibility
        "info": 0,      # Maintained for backward compatibility
        "confirmed": 0,
        "potential": 0,
        "blocked": 0,
        "skipped": 0,
        "not_tested": 0,
        "total": 0      # Total confirmed vulnerabilities
    }

    # Deduplicate findings so accidental duplicate records do not inflate dashboard counts
    seen_keys = set()
    deduped_findings = []
    for f in (findings or []):
        f_type = getattr(f, "type", "")
        f_url = getattr(f, "url", "")
        f_param = getattr(f, "parameter", "")
        f_title = getattr(f, "title", "")
        key = (f_type, f_url, f_param, f_title)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_findings.append(f)

    recorded_modules = set()

    for f in deduped_findings:
        cat = map_finding_to_category(f)
        sev = (getattr(f, "severity", None) or "").lower()
        v_status = (getattr(f, "verification_status", None) or "").upper()
        f_status = (getattr(f, "status", None) or "").upper()
        f_type = getattr(f, "type", "")
        if f_type:
            recorded_modules.add(f_type.lower())

        # Determine verification status
        effective_verif = v_status
        if not effective_verif:
            if f_status in ("SCANNER_ERROR", "ERROR"):
                effective_verif = "ERROR"
            elif f_status == "NOT_DETECTED":
                effective_verif = "NOT_DETECTED"
            elif f_status == "INCONCLUSIVE":
                effective_verif = "INCONCLUSIVE"
            elif f_status in ("BLOCKED", "SKIPPED", "NOT_TESTED", "POTENTIAL", "CONFIRMED"):
                effective_verif = f_status
            elif f_status in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if (getattr(f, "confidence", None) or "").upper() == "LOW" or "potential" in (getattr(f, "title", "") or "").lower():
                    effective_verif = "POTENTIAL"
                else:
                    effective_verif = "CONFIRMED"
            else:
                effective_verif = "POTENTIAL"

        # Tally verification status
        if effective_verif == "CONFIRMED":
            c["confirmed"] += 1
        elif effective_verif == "POTENTIAL":
            c["potential"] += 1
        elif effective_verif == "BLOCKED":
            c["blocked"] += 1
        elif effective_verif == "SKIPPED":
            c["skipped"] += 1
        elif effective_verif == "NOT_TESTED":
            c["not_tested"] += 1

        # Tally primary outcome categories
        if cat == "SCANNER_ERROR":
            c["scanner_error"] += 1
        elif cat == "NOT_DETECTED":
            c["not_detected"] += 1
        elif cat == "INCONCLUSIVE":
            c["inconclusive"] += 1
        elif cat == "HIGH":
            c["high"] += 1
            if sev == "critical":
                c["critical"] += 1
            c["total"] += 1
        elif cat == "MEDIUM":
            c["medium"] += 1
            c["total"] += 1
        elif cat == "LOW":
            c["low"] += 1
            if sev == "info":
                c["info"] += 1
            c["total"] += 1

    # If scan is supplied with module execution telemetry, account for clean/failed checks not in findings
    if scan is not None:
        module_details = None
        if hasattr(scan, "modules") and isinstance(scan.modules, dict):
            module_details = scan.modules.get("module_details", scan.modules)
        elif hasattr(scan, "checks") and isinstance(scan.checks, dict):
            module_details = scan.checks.get("module_details")

        if module_details and isinstance(module_details, dict):
            for mod_k, mod_v in module_details.items():
                if not isinstance(mod_v, dict):
                    continue
                k_lower = mod_k.lower()
                if k_lower in recorded_modules:
                    continue  # Already accounted for in findings
                st = (mod_v.get("status") or "").lower()
                sel = mod_v.get("selected", True)
                if not sel or st == "skipped":
                    c["skipped"] += 1
                elif st == "completed" and (mod_v.get("findings") or 0) == 0:
                    c["not_detected"] += 1
                elif st == "failed":
                    c["scanner_error"] += 1
                elif st == "inconclusive":
                    c["inconclusive"] += 1
                elif st == "blocked":
                    c["blocked"] += 1

    return c


# ==============================================================================
# 2. EVIDENCE-GROUNDED SAFE FALLBACK GENERATOR
# ==============================================================================

def build_deterministic_executive_summary(
    scan: Any,
    counts: Dict[str, int],
    supported_findings: List[Any],
    limitations: List[str]
) -> Dict[str, Any]:
    """
    Generates a deterministic, professional executive summary directly from
    verified scan data. Used as a primary builder or instant safe fallback.
    """
    target = getattr(scan, "target_url", "the target")
    score = getattr(scan, "security_score", None)
    score_str = f"{score}/100" if score is not None else "N/A"
    total_vulns = counts["high"] + counts["medium"] + counts["low"]

    # A. Security Overview (40-60 words)
    if total_vulns == 0:
        if counts["inconclusive"] > 0 and counts["not_detected"] == 0:
            overview = (
                f"EthioSec Scanner completed an automated security assessment of {target}. "
                f"Testing was inconclusive because no candidate query parameters or interactive HTML form inputs were discovered on evaluated pages. "
                f"No vulnerabilities were confirmed, but the target cannot be verified as secure without candidate input coverage."
            )
        elif counts["inconclusive"] > 0:
            overview = (
                f"EthioSec Scanner completed an automated security assessment of {target} with a security score of "
                f"{score_str}. Evaluated baseline checks completed without detecting vulnerabilities, but {counts['inconclusive']} "
                f"selected check(s) had coverage limitations and could not be conclusively tested. Authenticated follow-up testing is recommended."
            )
        else:
            overview = (
                f"EthioSec Scanner completed an automated security assessment of {target} with a security score of "
                f"{score_str}. All evaluated checks completed without detecting vulnerabilities. The attack surface "
                f"shows adherence to standard baseline controls for tested endpoints. Routine monitoring is recommended."
            )
    elif counts["high"] > 0:
        overview = (
            f"The automated security assessment of {target} identified {total_vulns} confirmed vulnerability item(s) "
            f"and achieved a security score of {score_str}. The primary operational concern is {counts['high']} "
            f"high-severity finding(s) that require immediate remediation to prevent unauthorized data access or system compromise."
        )
    else:
        overview = (
            f"The automated security assessment of {target} completed with a security score of {score_str}, uncovering "
            f"{total_vulns} security finding(s). The detected issues represent configuration and defense-in-depth "
            f"improvements rather than immediate critical exploits. Remediation will strengthen the overall security baseline."
        )

    # C. Top Risks (up to 3 supported findings)
    top_risks = []
    for f in supported_findings[:3]:
        cat = map_finding_to_category(f)
        endpoint = getattr(f, "url", None) or "Target endpoint"
        if getattr(f, "parameter", None):
            endpoint += f" (parameter: {getattr(f, 'parameter')})"

        # Short risk sentence
        risk_sentence = (getattr(f, "impact", None) or getattr(f, "description", None) or "Exposes application to security risk.")
        risk_sentence = risk_sentence.split(".")[0].strip() + "."
        if len(risk_sentence) > 120:
            risk_sentence = risk_sentence[:117] + "..."

        # Clear recommended action
        remediation_list = getattr(f, "remediation", [])
        if isinstance(remediation_list, list) and len(remediation_list) > 0 and remediation_list[0]:
            action = str(remediation_list[0]).strip()
        else:
            action = "Apply defensive validation and verify security configuration."

        top_risks.append({
            "title": getattr(f, "title", "Security Finding"),
            "severity": cat,
            "endpoint": endpoint,
            "risk": risk_sentence,
            "action": action
        })

    # D. What to Fix First (prioritized action list)
    what_to_fix_first = []
    if counts["high"] > 0:
        high_titles = [getattr(f, "title", "high-risk finding") for f in supported_findings if map_finding_to_category(f) == "HIGH"]
        titles_sample = ", ".join(high_titles[:2])
        what_to_fix_first.append(f"Remediate high-priority risks first ({titles_sample}) to mitigate critical exposure.")
    if counts["medium"] > 0:
        what_to_fix_first.append("Address medium-priority configuration issues to eliminate intermediate attack vectors.")
    if counts["low"] > 0:
        what_to_fix_first.append("Review low-priority items and implement defense-in-depth hardening.")
    if counts["inconclusive"] > 0:
        what_to_fix_first.append("Verify target endpoint URL parameters or provide authentication credentials to enable full test coverage.")
    elif counts["scanner_error"] > 0:
        what_to_fix_first.append("Investigate scanner errors and inconclusive checks to establish complete assessment coverage.")
    if not what_to_fix_first:
        what_to_fix_first.append("Maintain baseline configuration hygiene and repeat scans during regular release cycles.")

    # E. Scan Limitations
    if limitations:
        scan_limitations = " ".join(limitations)
    elif counts["scanner_error"] > 0:
        scan_limitations = f"{counts['scanner_error']} check(s) encountered network timeouts or host reachability warnings and could not be evaluated reliably."
    elif counts["inconclusive"] > 0:
        scan_limitations = f"{counts['inconclusive']} check(s) had coverage limitations (untested parameters or insufficient evidence) and require follow-up testing."
    else:
        scan_limitations = ""

    # F. Final Note
    final_note = (
        "This security assessment reflects the specific automated checks performed at scan time. "
        "It does not replace comprehensive penetration testing or guarantee the absence of untested vulnerabilities."
    )

    return {
        "security_overview": overview,
        "counts": {
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "not_detected": counts["not_detected"],
            "scanner_error": counts["scanner_error"]
        },
        "top_risks": top_risks,
        "what_to_fix_first": what_to_fix_first,
        "scan_limitations": scan_limitations,
        "final_note": final_note
    }


# ==============================================================================
# 3. STRUCTURED PROMPT & VALIDATION PIPELINE
# ==============================================================================

EXECUTIVE_SUMMARY_SYSTEM_INSTRUCTION = """You are a senior Application Security Specialist and Technical Reporting Lead for the EthioSec Web Vulnerability Scanner.
Generate a concise, professional executive security summary based STRICTLY on the verified scanner data provided.

STRICT CONSTRAINTS:
1. Grounding: The scanner is the absolute source of truth. Never invent findings, endpoints, statistics, or CVEs.
2. Structure: You MUST return a single valid JSON object with EXACTLY these keys:
   - "security_overview": A plain-language paragraph of approximately 40-60 words explaining what the scan found and the most important concern.
   - "top_risks": An array of up to 3 objects for the most critical supported findings. Each object must have:
       * "title": string (matching supported finding title)
       * "severity": string ("HIGH", "MEDIUM", or "LOW")
       * "endpoint": string (affected endpoint or component)
       * "risk": string (one short sentence explaining the real-world business risk)
       * "action": string (one clear recommended action)
     If no vulnerabilities were detected, this array MUST be empty [].
   - "what_to_fix_first": An array of prioritized action strings. Only include actions relevant to the actual scan findings.
   - "scan_limitations": A short explanation of recorded scanner errors or incomplete checks. If none were recorded, return an empty string "".
   - "final_note": A short professional reminder that a scan represents the checks performed at that time and does not prove the entire application is secure.
3. Tone: Simple, professional English. Short sentences. No generic filler (do not say "cybersecurity is paramount" or "in today's digital landscape").
4. Word Count: Keep the entire executive summary concise (aim for roughly 100-180 words total).
5. Never claim an issue is exploitable unless supported by recorded evidence.
6. Return ONLY the raw JSON object. Do not wrap in markdown quotes if possible.
"""

def extract_json_payload(text: str) -> Optional[Dict[str, Any]]:
    """Robustly extracts JSON from an LLM response string."""
    if not text or not isinstance(text, str):
        return None
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    # Try direct parse
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # Try regex match for JSON object
    match = re.search(r'(\{[\s\S]*\})', text)
    if match:
        try:
            data = json.loads(match.group(1))
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    return None


async def generate_executive_summary(
    scan: Any,
    findings: List[Any],
    ai_callable: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Generates a structured, evidence-grounded AI executive summary for a scan.
    Computes verified 5-category counts in Python first, queries Gemini/Ollama,
    validates the output against real scan evidence, and falls back gracefully.
    """
    # 1. Compute verified 5-category counts in backend code
    counts = aggregate_finding_counts(findings)

    # 2. Extract supported, confirmed findings (sorted by severity)
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    confirmed_findings = [
        f for f in findings
        if map_finding_to_category(f) in ("HIGH", "MEDIUM", "LOW")
    ]
    confirmed_findings.sort(
        key=lambda x: severity_order.get(map_finding_to_category(x), 9)
    )

    # 3. Extract limitations (errors or inconclusive checks)
    limitations = []
    error_findings = [f for f in findings if map_finding_to_category(f) == "SCANNER_ERROR"]
    inconclusive_findings = [f for f in findings if map_finding_to_category(f) == "INCONCLUSIVE"]
    if error_findings:
        limitations.append(f"{len(error_findings)} check(s) encountered scanner execution errors or network timeouts.")
    if inconclusive_findings:
        limitations.append(f"{len(inconclusive_findings)} check(s) produced insufficient evidence to establish a definitive result.")

    # 4. Generate fallback summary first (used if AI is unavailable or fails)
    fallback = build_deterministic_executive_summary(scan, counts, confirmed_findings, limitations)

    # 5. If no AI callable provided, import ask_ai
    if ai_callable is None:
        try:
            from .service import ask_ai
            ai_callable = ask_ai
        except Exception as e:
            logger.warning(f"Could not import ask_ai; returning verified fallback: {e}")
            return fallback

    # 6. Prepare prompt with verified data
    target_url = getattr(scan, "target_url", "the target")
    score = getattr(scan, "security_score", None)
    score_display = f"{score}/100" if score is not None else "N/A"
    depth = getattr(scan, "depth", "standard")

    findings_summary = []
    for f in confirmed_findings[:5]:
        cat = map_finding_to_category(f)
        url = getattr(f, "url", None) or "N/A"
        param = getattr(f, "parameter", None) or "None"
        findings_summary.append(
            f"- [{cat}] {getattr(f, 'title', 'Issue')} at {url} (Param: {param}). "
            f"Evidence snippet: {str(getattr(f, 'evidence', '') or '')[:120]}"
        )

    user_prompt = f"""VERIFIED SCAN DATA (SOURCE OF TRUTH):
- Target: {target_url}
- Scan Depth: {depth}
- Security Score: {score_display}
- Total Confirmed Findings: {counts['high'] + counts['medium'] + counts['low']}
- VERIFIED COUNTS (Do not alter):
  * High: {counts['high']}
  * Medium: {counts['medium']}
  * Low: {counts['low']}
  * Not Detected: {counts['not_detected']}
  * Scanner Error: {counts['scanner_error']}

SUPPORTED FINDINGS:
{chr(10).join(findings_summary) if findings_summary else "No vulnerabilities detected."}

LIMITATIONS NOTED:
{chr(10).join(limitations) if limitations else "None recorded."}

Return the structured JSON executive summary following all instructions."""

    try:
        reply = await ai_callable(EXECUTIVE_SUMMARY_SYSTEM_INSTRUCTION, user_prompt)
        parsed = extract_json_payload(reply)

        if not parsed or not isinstance(parsed, dict):
            logger.info("AI response was not valid JSON; using verified fallback.")
            return fallback

        # Validate security_overview
        overview = str(parsed.get("security_overview", "")).strip()
        if not overview or len(overview) < 20:
            overview = fallback["security_overview"]
        elif counts["inconclusive"] > 0 and counts["not_detected"] == 0 and (counts["high"] + counts["medium"] + counts["low"]) == 0:
            # When testing had zero input coverage and zero completed clean checks, force truthful inconclusive overview
            overview = fallback["security_overview"]

        # Strictly enforce backend-calculated counts
        verified_counts_dict = {
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "not_detected": counts["not_detected"],
            "scanner_error": counts["scanner_error"]
        }

        # Validate top_risks (must not invent findings if none exist)
        validated_top_risks = []
        if counts["high"] + counts["medium"] + counts["low"] == 0:
            validated_top_risks = []
        else:
            raw_risks = parsed.get("top_risks", [])
            if isinstance(raw_risks, list) and len(raw_risks) > 0:
                for item in raw_risks[:3]:
                    if isinstance(item, dict) and item.get("title"):
                        # Match severity against confirmed categories
                        sev = str(item.get("severity", "LOW")).upper()
                        if sev not in ("HIGH", "MEDIUM", "LOW"):
                            sev = "MEDIUM"
                        validated_top_risks.append({
                            "title": str(item.get("title", "")).strip()[:150],
                            "severity": sev,
                            "endpoint": str(item.get("endpoint", "Target endpoint")).strip()[:200],
                            "risk": str(item.get("risk", "Exposes potential security risk.")).strip()[:250],
                            "action": str(item.get("action", "Apply defensive remediation.")).strip()[:250]
                        })
            if not validated_top_risks:
                validated_top_risks = fallback["top_risks"]

        # Validate what_to_fix_first
        raw_fix = parsed.get("what_to_fix_first", [])
        validated_fix = []
        if isinstance(raw_fix, list) and len(raw_fix) > 0:
            for act in raw_fix[:5]:
                if isinstance(act, str) and act.strip():
                    validated_fix.append(act.strip())
        if not validated_fix:
            validated_fix = fallback["what_to_fix_first"]
        elif counts["inconclusive"] > 0 and (counts["high"] + counts["medium"] + counts["low"]) == 0:
            if not any("coverage" in act.lower() or "untested" in act.lower() for act in validated_fix):
                validated_fix = fallback["what_to_fix_first"]

        # Validate scan_limitations
        raw_limitations = parsed.get("scan_limitations", "")
        if counts["scanner_error"] == 0 and counts["inconclusive"] == 0:
            validated_limitations = ""
        else:
            validated_limitations = str(raw_limitations).strip() if raw_limitations else fallback["scan_limitations"]

        # Validate final_note
        final_note = str(parsed.get("final_note", "")).strip()
        if not final_note or len(final_note) < 20:
            final_note = fallback["final_note"]

        return {
            "security_overview": overview,
            "counts": verified_counts_dict,
            "top_risks": validated_top_risks,
            "what_to_fix_first": validated_fix,
            "scan_limitations": validated_limitations,
            "final_note": final_note
        }

    except Exception as e:
        logger.warning(f"Error calling AI for executive summary: {e}; using verified fallback.")
        return fallback


# ==============================================================================
# 4. MARKDOWN & TEXT SERIALIZERS
# ==============================================================================

def format_executive_summary_markdown(data: Dict[str, Any]) -> str:
    """
    Formats the structured executive summary into clean, readable Markdown
    for reports and AI chat responses.
    """
    c = data.get("counts", {})
    overview = data.get("security_overview", "")
    top_risks = data.get("top_risks", [])
    what_to_fix = data.get("what_to_fix_first", [])
    limitations = data.get("scan_limitations", "")
    final_note = data.get("final_note", "")

    lines = [
        "### A. SECURITY OVERVIEW",
        overview,
        "",
        "### B. FINDINGS AT A GLANCE",
        f"- High: {c.get('high', 0)}",
        f"- Medium: {c.get('medium', 0)}",
        f"- Low: {c.get('low', 0)}",
        f"- Not Detected: {c.get('not_detected', 0)}",
        f"- Scanner Error: {c.get('scanner_error', 0)}",
        "",
        "### C. TOP RISKS"
    ]

    if not top_risks:
        lines.append("No active vulnerabilities detected across evaluated checks.")
    else:
        for r in top_risks:
            lines.append(f"**[{r.get('severity', 'LOW')}] {r.get('title', 'Risk')}**")
            lines.append(f"- Location: `{r.get('endpoint', 'N/A')}`")
            lines.append(f"- Risk: {r.get('risk', '')}")
            lines.append(f"- Recommended Action: {r.get('action', '')}")
            lines.append("")

    lines.extend([
        "### D. WHAT TO FIX FIRST"
    ])
    for idx, item in enumerate(what_to_fix, 1):
        lines.append(f"{idx}. {item}")

    if limitations:
        lines.extend([
            "",
            "### E. SCAN LIMITATIONS",
            limitations
        ])

    lines.extend([
        "",
        "### F. FINAL NOTE",
        final_note
    ])

    return "\n".join(lines)
