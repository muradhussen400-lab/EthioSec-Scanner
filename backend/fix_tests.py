import os

with open('rewrite_ac_tests.py', 'r') as f:
    content = f.read()

# Fix query param
content = content.replace('"params": ["order_id=1"]', '"params": ["order_id"]')

# Fix form ID
content = content.replace('"data": {"item_id": 1}', '"params": ["item_id"], "data": {"item_id": 1}')

# Fix flat json
content = content.replace('"json": {"item_id": 1}', '"params": ["item_id"], "json": {"item_id": 1}')

# Fix nested json
content = content.replace('"json": {"payload": {"item_id": 1}}', '"params": ["item_id"], "json": {"payload": {"item_id": 1}}')

# Fix json array
content = content.replace('"json": {"ids": [1]}', '"params": ["ids"], "json": {"ids": [1]}')

# Fix secret redaction
content = content.replace('"A_Secret" not in findings[0].evidence', '"a_secret" not in findings[0].evidence.lower()')
content = content.replace('"B_Secret" not in findings[0].evidence', '"b_secret" not in findings[0].evidence.lower()')

# Write back
with open('rewrite_ac_tests.py', 'w') as f:
    f.write(content)
