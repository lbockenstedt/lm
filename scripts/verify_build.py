"""Quick pre-release sanity checks for the lm repo.

Checks that every core/src Python file compiles, that WebUI/index.html has no
truncated or unbalanced tags, and that VERSION looks like "X.Y" (or ".Y").
Exits 1 if any check fails so it can gate a build.
"""
# Exit with a status code that tells the caller whether the build passed.
import sys
# Regular expressions for the HTML and VERSION checks.
import re
# Path objects for building file locations and globbing.
from pathlib import Path

def check_python_syntax(file_path):
    """Compile one Python file; return (True, "") if it compiles, else (False, error text)."""
    # Compilation errors (and file errors) are reported rather than raised.
    try:
        # py_compile compiles a file to bytecode; doraise=True turns syntax errors into exceptions.
        import py_compile
        py_compile.compile(file_path, doraise=True)
        return True, ""
    except Exception as e:
        return False, str(e)

def check_html_tags(file_path):
    """Do a lightweight sanity check of an HTML file's tags; return (ok, message)."""
    # Read the whole HTML file into memory.
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Check for truncated tags (e.g., </div without the >)
    # This finds tags that start with < or </ but aren't closed by > before a newline or end of string
    # Looking for < followed by characters that are not >, then a newline or end of file.
    pattern = re.compile(r'<[^>]*(\n|$)', re.MULTILINE)
    matches = pattern.findall(content)
    # Any truncated tag fails the check immediately.
    if matches:
        return False, f"Found truncated tags: {matches}"

    # 2. Basic Tag Balance Check
    # We'll track opening and closing tags. 
    # Note: self-closing tags like <br/>, <img/>, <input/> are ignored.
    # Stack of currently open tag names; a closing tag must match the top.
    stack = []
    # Regex to find all tags: <(/?)(\w+)([^>]*)(\/?)>
    tag_pattern = re.compile(r'<(/?)(\w+)([^>]*)(\/?)>')
    
    # Look at every tag in the file in order.
    for match in tag_pattern.finditer(content):
        # Group 1 is "/" for closing tags, group 2 the tag name, group 4 "/" for <x/>.
        is_closing = match.group(1) == '/'
        tag_name = match.group(2).lower()
        is_self_closing = match.group(4) == '/'
        
        # Self-closing tags never need a matching close.
        if is_self_closing:
            continue
            
        # Closing tag: it must close the most recently opened tag.
        if is_closing:
            # Nothing open means a stray closing tag.
            if not stack:
                return False, f"Closing tag </{tag_name}> found without opening tag."
            # Pop the open tag and compare names.
            opening_tag = stack.pop()
            if opening_tag != tag_name:
                return False, f"Tag mismatch: expected </{opening_tag}>, found </{tag_name}>."
        # Opening tag: remember it unless it is a void element that has no closing tag.
        else:
            # Ignore common void elements that might not be self-closed in some HTML versions
            void_elements = {'meta', 'link', 'img', 'br', 'hr', 'input', 'source'}
            if tag_name not in void_elements:
                stack.append(tag_name)
                
    # Anything still open at the end was never closed.
    if stack:
        return False, f"Unclosed tags remaining: {', '.join(stack)}"
        
    return True, ""

def check_version_format(file_path):
    """Check that the VERSION file is non-empty and matches "X.Y" or ".Y"; return (ok, message)."""
    # File read errors are reported as failures rather than crashing.
    try:
        # Read the file and trim whitespace/newlines.
        with open(file_path, 'r') as f:
            content = f.read().strip()
            # An empty file is not a valid version.
            if not content:
                return False, "VERSION file is empty"
            # Check for common version pattern (e.g. 0.24, or the post-reset
            # sentinel ".01" which has no leading digit).
            if not re.match(r'^\d*\.\d+$', content):
                return False, f"Invalid version format: {content}. Expected 'X.Y' or '.Y'"
        return True, ""
    except Exception as e:
        return False, str(e)

def main():
    """Run all checks, print a report, and exit 0 on success or 1 if any check failed."""
    # Repo location is hard-coded to the owner's workstation checkout.
    # Count of failed checks; any non-zero count fails the build.
    base_dir = Path("/Users/lbockenstedt/vscode/lm")
    errors = 0

    # 1. Python Files
    print("🔍 Checking Python syntax...")
    # Compile every Python file under core/src, recursively.
    for py_file in base_dir.glob("core/src/**/*.py"):
        ok, msg = check_python_syntax(str(py_file))
        # Report failures with their message and count them; show passes by file name.
        if not ok:
            print(f"  ❌ {py_file}: {msg}")
            errors += 1
        else:
            print(f"  ✅ {py_file.name}")

    # 2. HTML Validation
    print("\n🔍 Validating HTML tags in index.html...")
    # The main web UI page whose tags we validate.
    html_file = base_dir / "WebUI/index.html"
    # Only validate when the file exists; a missing UI page is itself an error.
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
    # The VERSION file at the repo root.
    ver_file = base_dir / "VERSION"
    # Validate the format when present; a missing VERSION file is an error.
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

    # Summarise: any errors -> exit code 1 so the calling script/CI stops.
    if errors > 0:
        print(f"\n🚩 Build failed with {errors} errors.")
        sys.exit(1)
    else:
        print("\n🎉 All robust checks passed!")
        sys.exit(0)

# Only run when executed as a script.
if __name__ == "__main__":
    main()
