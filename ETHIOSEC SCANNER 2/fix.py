import re

with open('livejava.js', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('if (viewResultsBtn) viewResultsBtn.href = \\\n', 'if (viewResultsBtn) viewResultsBtn.href = `')
content = content.replace('esults.html?id=\\\\;', 'results.html?id=${scanId}`;')
content = content.replace('fetch(\http://127.0.0.1:8000/api/scans/\/status\, {', 'fetch(`http://127.0.0.1:8000/api/scans/${scanId}/status`, {')
content = content.replace('headers: token ? { \'Authorization\': \Bearer \\\ } : {}', 'headers: token ? { \'Authorization\': `Bearer ${token}` } : {}')

with open('livejava.js', 'w', encoding='utf-8') as f:
    f.write(content)
