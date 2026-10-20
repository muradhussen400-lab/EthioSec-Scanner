import os
import glob

def fix_frontend(directory):
    for ext in ["*.js", "*.html"]:
        for filepath in glob.glob(os.path.join(directory, "**", ext), recursive=True):
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            # Fix status checks
            content = content.replace('status === "passed"', 'status === "NOT_DETECTED"')
            content = content.replace('status !== "passed"', 'status !== "NOT_DETECTED"')
            content = content.replace('status === "error"', 'status === "SCANNER_ERROR"')
            content = content.replace('status !== "error"', 'status !== "SCANNER_ERROR"')
            content = content.replace('status === "open"', 'status === "HIGH"')
            content = content.replace('status !== "open"', 'status !== "HIGH"')

            # Fix filters
            content = content.replace('filterSeverity === "passed"', 'filterSeverity === "not_detected"')
            content = content.replace('filterSeverity === "open"', 'filterSeverity === "high"')
            content = content.replace('["all", "open", "passed"]', '["all", "high", "not_detected"]')
            
            # HTML data-filters
            content = content.replace('data-filter="passed"', 'data-filter="not_detected"')
            content = content.replace('value="passed"', 'value="not_detected"')
            content = content.replace('data-filter="open"', 'data-filter="high"')
            content = content.replace('value="open"', 'value="high"')
            
            # Also mock/demo removal in results.html
            content = content.replace('|| "scan_demo"', '')

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
                
    print("Frontend fixed.")

if __name__ == "__main__":
    fix_frontend(r"c:\Users\Student\Downloads\insa project antigravity\ETHIOSEC SCANNER 2")
