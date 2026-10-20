import re, os

pages = ['dashboardfinal.html', 'scanfinal.html', 'scan_history.html', 'results.html', 'reports.html', 'assistant.html', 'settings.html']
for p in pages:
    path = os.path.join('ETHIOSEC SCANNER 2', p)
    with open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    print('PAGE:', p)
    css_matches = re.findall(r'<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"', html)
    print('  CSS:', css_matches)
    links = re.findall(r'href="([^"]+)"[^>]*class="[^"]*side-link[^"]*"', html)
    if not links:
        links = re.findall(r'class="[^"]*side-link[^"]*"[^>]*href="([^"]+)"', html)
    print('  Sidebar Links:', links)
