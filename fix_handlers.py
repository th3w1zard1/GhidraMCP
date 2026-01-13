#!/usr/bin/env python3
"""
Script to add exception handling to all HTTP handlers in GhidraMCPPlugin.java
"""
import re

# Read the file
with open('src/main/java/com/th3w1zard1/GhidraMCPPlugin.java', 'r', encoding='utf-8') as f:
    content = f.read()

# Pattern to find handlers without try-catch
# We'll manually fix the ones that need fixing
# For now, let's just identify which handlers still need wrapping

pattern = r'server\.createContext\("([^"]+)", exchange -> \{([^}]+)\}\);'
matches = re.finditer(pattern, content, re.DOTALL)

handlers_to_fix = []
for match in matches:
    endpoint = match.group(1)
    handler_body = match.group(2).strip()
    # Check if handler already has try-catch
    if 'try {' not in handler_body and 'sendResponse' in handler_body:
        handlers_to_fix.append(endpoint)

print(f"Found {len(handlers_to_fix)} handlers that need exception handling:")
for endpoint in handlers_to_fix:
    print(f"  - {endpoint}")
