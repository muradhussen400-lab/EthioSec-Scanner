import os
import re

files = [
    "assistant.html", "dashboardfinal.html", "livescan.html", 
    "reports.html", "results.html", "scanfinal.html", 
    "scan_history.html", "settings.html"
]

nav_template = '''      <nav class="sidebar-nav">
        <a href="dashboardfinal.html" class="side-link{active_dashboard}"><span class="side-icon">📊</span> Dashboard</a>
        <a href="scanfinal.html" class="side-link{active_scan}"><span class="side-icon">⚡</span> New Scan</a>
        <a href="scan_history.html" class="side-link{active_history}"><span class="side-icon">🕒</span> History</a>
        <a href="results.html" class="side-link{active_results}"><span class="side-icon">📈</span> Results</a>
        <a href="reports.html" class="side-link{active_reports}"><span class="side-icon">📄</span> Reports</a>
        <a href="assistant.html" class="side-link{active_assistant}"><span class="side-icon">🤖</span> AI Assistant</a>
        <div class="nav-divider" style="margin: 15px 0; border-top: 1px solid rgba(255,255,255,0.1);"></div>
        <a href="settings.html" class="side-link{active_settings}"><span class="side-icon">⚙️</span> Settings</a>
        <a href="#" class="side-link" onclick="logout(event)"><span class="side-icon">🚪</span> Logout</a>
      </nav>
      
      <script>
        function logout(e) {{
            e.preventDefault();
            localStorage.removeItem("isLoggedIn");
            localStorage.removeItem("userEmail");
            localStorage.removeItem("token");
            window.location.href = "login.html";
        }}
      </script>'''

for f in files:
    if not os.path.exists(f): continue
    
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
        
    active = {
        'active_dashboard': ' active' if f == 'dashboardfinal.html' else '',
        'active_scan': ' active' if f in ['scanfinal.html', 'livescan.html'] else '',
        'active_history': ' active' if f == 'scan_history.html' else '',
        'active_results': ' active' if f == 'results.html' else '',
        'active_reports': ' active' if f == 'reports.html' else '',
        'active_assistant': ' active' if f == 'assistant.html' else '',
        'active_settings': ' active' if f == 'settings.html' else ''
    }
    
    new_nav = nav_template.format(**active)
    
    pattern = re.compile(r'<nav class="sidebar-nav">.*?</nav>', re.DOTALL)
    if pattern.search(content):
        content = pattern.sub(new_nav, content)
        with open(f, 'w', encoding='utf-8') as file:
            file.write(content)

