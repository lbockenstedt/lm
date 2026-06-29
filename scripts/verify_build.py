import os
import sys
import re
from pathlib import Path

def check_python_syntax(file_path):
    try:
        import py_compile
        py_compile.compile(file_path, doraise=True)
        return True, ""
    except Exception as e:
        return False, str(e)

def check_html_tags(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Check for truncated tags (e.g., </div without the >)
    # This finds tags that start with < or </ but aren't closed by > before a newline or end of string
    # Looking for < followed by characters that are not >, then a newline or end of file.
    pattern = re.compile(r'<[^>]*(\n|$)', re.MULTILINE)
    matches = pattern.findall(content)
    if matches:
        return False, f"Found truncated tags: {matches}"

    # 2. Basic Tag Balance Check
    # We'll track opening and closing tags. 
    # Note: self-closing tags like <br/>, <img/>, <input/> are ignored.
    stack = []
    # Regex to find all tags: <(/?)(\w+)([^>]*)(\/?)>
    tag_pattern = re.compile(r'<(/?)(\w+)([^>]*)(\/?)>')
    
    for match in tag_pattern.finditer(content):
        is_closing = match.group(1) == '/'
        tag_name = match.group(2).lower()
        is_self_closing = match.group(4) == '/'
        
        if is_self_closing:
            continue
            
        if is_closing:
            if not stack:
                return False, f"Closing tag </{tag_name}> found without opening tag."
            opening_tag = stack.pop()
            if opening_tag != tag_name:
                return False, f"Tag mismatch: expected </{opening_tag}>, found </{tag_name}>."
        else:
            # Ignore common void elements that might not be self-closed in some HTML versions
            void_elements = {'meta', 'link', 'img', 'br', 'hr', 'input', 'source'}
            if tag_name not in void_elements:
                stack.append(tag_name)
                
    if stack:
        return False, f"Unclosed tags remaining: {', '.join(stack)}"
        
    return True, ""

def check_version_format(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return False, "VERSION file is empty"
            # Check for common version pattern (e.g. 0.24)
            if not re.match(r'^\d+\.\d+$', content):
                return False, f"Invalid version format: {content}. Expected 'X.Y'"
        return True, ""
    except Exception as e:
        return False, str(e)

def main():
    base_dir = Path("/Users/lbockenstedt/vscode/lm")
    errors = 0

    # 1. Python Files
    print("🔍 Checking Python syntax...")
    for py_file in base_dir.glob("core/src/**/*.py"):
        ok, msg = check_python_syntax(str(py_file))
        if not ok:
            print(f"  ❌ {py_file}: {msg}")
            errors += 1
        else:
            print(f"  ✅ {py_file.name}")

    # 2. HTML Validation
    print("\n🔍 Validating HTML tags in index.html...")
    html_file = base_dir / "WebUI/index.html"
    if html_file.exists():
        ok, msg = check_html_tags(str(html_file))
        if not ok:
            print(f"  ❌ HTML Error: {msg}")
            errors += 1
        else:
            print("  ✅ index.html tags are balanced and closed.")
    else:
        print("  ❌ index.html not found!")
        errors += 1

    # 3. Version Check
    print("\n🔍 Verifying VERSION format...")
    ver_file = base_dir / "VERSION"
    if ver_file.exists():
        ok, msg = check_version_format(str(ver_file))
        if not ok:
            print(f"  ❌ {msg}")
            errors += 1
        else:
            print(f"  ✅ VERSION format is correct.")
    else:
        print("  ❌ VERSION file missing!")
        errors += 1

    if errors > 0:
        print(f"\n🚩 Build failed with {errors} errors.")
        sys.exit(1)
    else:
        print("\n🎉 All robust checks passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()
