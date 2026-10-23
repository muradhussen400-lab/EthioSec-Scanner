import os
import re

files = [
    "dashboardfinal.html", "scanfinal.html", "livescan.html",
    "results.html", "scan_history.html", "reports.html",
    "assistant.html", "settings.html"
]

auth_script = '''    <script>
        if (localStorage.getItem("isLoggedIn") !== "true") {
            window.location.href = "login.html";
        }
        
        // Professional 401 Unauthorized handling
        const originalFetch = window.fetch;
        window.fetch = async function() {
            const response = await originalFetch.apply(this, arguments);
            if (response.status === 401) {
                localStorage.removeItem("isLoggedIn");
                localStorage.removeItem("token");
                localStorage.removeItem("userEmail");
                window.location.href = "login.html";
            }
            return response;
        };
    </script>
'''

for f in files:
    if not os.path.exists(f): continue
    with open(f, "r", encoding="utf-8") as file:
        content = file.read()
    
    if "localStorage.getItem(\"isLoggedIn\") !== \"true\"" not in content:
        # Insert right after <head>
        content = re.sub(r'(<head.*?>)', r'\1\n' + auth_script, content, flags=re.IGNORECASE)
        with open(f, "w", encoding="utf-8") as file:
            file.write(content)

print("Auth protection applied to all authenticated pages.")
