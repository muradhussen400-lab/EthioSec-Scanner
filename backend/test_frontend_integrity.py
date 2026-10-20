import re
from pathlib import Path

def test_html_and_js_elements_integrity():
    workspace = Path(__file__).resolve().parent.parent
    html_path = workspace / "ETHIOSEC SCANNER 2" / "livescan.html"
    js_path = workspace / "ETHIOSEC SCANNER 2" / "livejava.js"
    css_path = workspace / "ETHIOSEC SCANNER 2" / "livestyle.css"

    assert html_path.exists(), "livescan.html must exist"
    assert js_path.exists(), "livejava.js must exist"
    assert css_path.exists(), "livestyle.css must exist"

    html_content = html_path.read_text(encoding="utf-8")
    js_content = js_path.read_text(encoding="utf-8")
    css_content = css_path.read_text(encoding="utf-8")

    # 1. Essential IDs in HTML
    essential_ids = [
        "ringProgress",
        "progressPercent",
        "progressFill",
        "stageText",
        "stageHint",
        "statusLabel",
        "scanIdLabel",
        "depthLabel",
        "elapsed",
        "scanTarget",
        "scanTargetLink",
        "viewResults",
        "cancelScan",
        "checkGrid",
        "pipelineTrack",
        "pipelineList",
        "scanNoticeBox",
        "copyScanIdBtn",
        "streamPulseDot",
        "streamStatusText",
        "sidebarTelemetryText",
        "telemetryStatusDot",
        "detailsTargetUrl",
        "detailsProfile",
        "detailsMaxPages",
        "detailsMaxDepth",
        "detailsSelectedChecks",
        "openDetailsModalBtn",
        "detailsModalBackdrop",
        "closeDetailsModalBtn",
        "detailsModalBody"
    ]

    for element_id in essential_ids:
        assert f'id="{element_id}"' in html_content or f"id='{element_id}'" in html_content, f"Element #{element_id} must exist in livescan.html"

    # 2. Check all getElementById in JS exist in HTML
    get_element_ids = re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_content)
    for element_id in get_element_ids:
        assert f'id="{element_id}"' in html_content or f"id='{element_id}'" in html_content, f"JS element #{element_id} must exist in livescan.html"

    # 3. Canonical 7 Pipeline Stages
    expected_stages = [
        "target_validation",
        "dns_reachability",
        "security_headers",
        "auth",
        "access_control",
        "vuln_checks",
        "report_generation"
    ]
    for stage in expected_stages:
        assert stage in js_content, f"Pipeline stage {stage} must be handled in livejava.js"

    # 4. Canonical 12 Modules
    expected_modules = [
        "sqli", "xss", "headers", "cookies", "cors", "https",
        "auth", "access_control", "exposed_files", "http_methods",
        "info_disclosure", "misconfig"
    ]
    for mod in expected_modules:
        assert f'id: "{mod}"' in js_content, f"Canonical module {mod} must be defined in livejava.js"

    # 5. Check CSS classes
    expected_css_classes = [
        ".pipeline-stage-step",
        ".pipeline-stage-step.completed",
        ".pipeline-stage-step.running",
        ".pipeline-stage-step.failed",
        ".pipeline-stage-step.skipped",
        ".mod-card",
        ".mod-card.completed",
        ".mod-card.running",
        ".mod-card.failed",
        ".mod-card.skipped",
        ".timeline-item",
        ".timeline-item.completed",
        ".timeline-item.running",
        ".timeline-item.failed",
        ".ring-progress"
    ]
    for css_cls in expected_css_classes:
        assert css_cls in css_content, f"CSS class {css_cls} must be defined in livestyle.css"

    # 6. Verify reduced-motion support in CSS
    assert "@media (prefers-reduced-motion: reduce)" in css_content, "prefers-reduced-motion must be supported in livestyle.css"

    # 7. Verify security: escapeHTML usage in JS
    assert "function escapeHTML(" in js_content, "escapeHTML helper must be defined in livejava.js"
    assert "escapeHTML(evt.title)" in js_content, "Event titles must be HTML-escaped in livejava.js"
    assert "escapeHTML(evt.msg)" in js_content, "Event messages must be HTML-escaped in livejava.js"
    # 8. Verify Mock Data Elimination
    dashboard_js = (workspace / "ETHIOSEC SCANNER 2" / "dashboardfinal.js").read_text(encoding="utf-8")
    assert "const MOCKUP_SCANS" not in dashboard_js, "MOCKUP_SCANS must be eliminated from dashboardfinal.js"
    assert 'const API_BASE = "http://127.0.0.1:8000/api";' in dashboard_js, "API_BASE in dashboardfinal.js must be http://127.0.0.1:8000/api"

    settings_js = (workspace / "ETHIOSEC SCANNER 2" / "settingsjava.js").read_text(encoding="utf-8")
    assert '"Miftah Hussen"' not in settings_js, "Hardcoded fallback 'Miftah Hussen' must be eliminated from settingsjava.js"

    mockapi_js = (workspace / "ETHIOSEC SCANNER 2" / "mockapi.js").read_text(encoding="utf-8")
    assert "DEPRECATED LEGACY MOCK FIXTURE" in mockapi_js, "mockapi.js must have deprecation header"

    # Verify mockapi.js is not loaded in production HTML
    prod_html_files = [
        "dashboardfinal.html", "scanfinal.html", "livescan.html",
        "results.html", "reports.html", "scan_history.html",
        "assistant.html", "settings.html", "login.html", "signup.html"
    ]
    for p_html in prod_html_files:
        p_content = (workspace / "ETHIOSEC SCANNER 2" / p_html).read_text(encoding="utf-8")
        assert "mockapi.js" not in p_content, f"mockapi.js must not be included in {p_html}"

    print("All frontend integrity tests passed!")

def test_new_scan_ui_changes():
    workspace = Path(__file__).resolve().parent.parent
    scan_html_path = workspace / "ETHIOSEC SCANNER 2" / "scanfinal.html"
    scan_js_path = workspace / "ETHIOSEC SCANNER 2" / "scanjavafinal.js"

    assert scan_html_path.exists(), "scanfinal.html must exist"
    assert scan_js_path.exists(), "scanjavafinal.js must exist"

    html_content = scan_html_path.read_text(encoding="utf-8")
    js_content = scan_js_path.read_text(encoding="utf-8")

    # Change 1: Target field starts blank and has email autofill protections
    assert 'id="targetUrl"' in html_content
    assert 'value=""' in html_content
    assert 'targetUrlInput.value = "";' in js_content
    assert "Target URL cannot be blank" in js_content

    # Change 2: Recent Targets section removed
    assert "recentTargetsGroup" not in html_content
    assert "recent-chip" not in html_content
    assert "recent-chip" not in js_content

    # Change 3: Simplify Security Check selection list (descriptions removed, names only)
    assert '<p class="check-desc">' not in html_content
    canonical_modules = [
        "sqli", "xss", "headers", "cookies", "cors", "https",
        "auth", "access_control", "exposed_files", "http_methods",
        "info_disclosure", "misconfig"
    ]
    for mod in canonical_modules:
        assert f'data-module="{mod}"' in html_content, f"Check card for {mod} must exist in scanfinal.html"

    # Change 4: Remove confusing page/depth text from visible profile cards
    # cardStandard and cardDeep must not contain profile-limits
    card_standard_match = re.search(r'id="cardStandard"[^>]*>(.*?)</div>\s*<!-- Deep Scan Card -->', html_content, re.DOTALL)
    assert card_standard_match, "cardStandard must exist"
    assert "profile-limits" not in card_standard_match.group(1), "profile-limits must be removed from cardStandard"
    assert "Max pages" not in card_standard_match.group(1), "Max pages text must be removed from cardStandard"
    assert "Max depth" not in card_standard_match.group(1), "Max depth text must be removed from cardStandard"

    card_deep_match = re.search(r'id="cardDeep"[^>]*>(.*?)</div>\s*<!-- Super Scan Card', html_content, re.DOTALL)
    assert card_deep_match, "cardDeep must exist"
    assert "profile-limits" not in card_deep_match.group(1), "profile-limits must be removed from cardDeep"
    assert "Max pages" not in card_deep_match.group(1), "Max pages text must be removed from cardDeep"
    assert "Max depth" not in card_deep_match.group(1), "Max depth text must be removed from cardDeep"

    print("All New Scan UI integrity assertions passed!")

if __name__ == "__main__":
    test_html_and_js_elements_integrity()
    test_new_scan_ui_changes()

