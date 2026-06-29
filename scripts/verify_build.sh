#!/bin/bash
set -e

echo "🚀 Starting Hub Build Verification..."

# 1. Python Syntax Check
echo "🔍 Checking Python syntax..."
for file in $(find /Users/lbockenstedt/vscode/lm/core/src -name "*.py"); do
    python3 -m py_compile "$file" || { echo "❌ Syntax error in $file"; exit 1; }
done
echo "✅ Python syntax checks passed."

# 2. JavaScript Syntax Check
echo "🔍 Checking JavaScript syntax..."
# We use node -c to check syntax without executing
if command -v node >/dev/null 2>&1; then
    node -c /Users/lbockenstedt/vscode/lm/WebUI/main.js || { echo "❌ Syntax error in WebUI/main.js"; exit 1; }
    echo "✅ JavaScript syntax checks passed."
else
    echo "⚠️  Node.js not found, skipping JS syntax check."
fi

# 3. Version File Check
echo "🔍 Verifying VERSION file..."
if [ ! -f /Users/lbockenstedt/vscode/lm/VERSION ]; then
    echo "❌ VERSION file missing!"
    exit 1
fi
echo "✅ VERSION file exists."

# 4. HTML Balance Check (Simple)
echo "🔍 Performing basic HTML check..."
# This is a naive check just to ensure the file isn't truncated or obviously broken
if grep -q "</html" /Users/lbockenstedt/vscode/lm/WebUI/index.html; then
    echo "✅ index.html looks complete."
else
    echo "❌ index.html may be truncated or missing closing tags."
    exit 1
fi

echo "🎉 All build verification checks passed!"
