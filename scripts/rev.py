import sys
import os

def rev_version(version_file):
    if not os.path.exists(version_file):
        print(f"Error: Version file {version_file} not found.")
        sys.exit(1)

    with open(version_file, "r") as f:
        current_version = f.read().strip()

    try:
        parts = current_version.split('.')
        if len(parts) != 2:
            raise ValueError("Version must be in Major.Minor format")

        major = int(parts[0])
        minor_str = parts[1]
        minor = int(minor_str)

        minor += 1
        if minor >= 10 ** len(minor_str): # Simple rule: if minor overflows its current digit count, bump major and reset minor
            major += 1
            minor = 0

        # Preserve leading zeros
        new_minor_str = str(minor).zfill(len(minor_str))
        new_version = f"{major}.{new_minor_str}"

        with open(version_file, "w") as f:
            f.write(new_version)

        print(f"Version bumped: {current_version} -> {new_version}")
        return new_version
    except Exception as e:
        print(f"Error parsing version: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Default to root VERSION file
    version_file = "VERSION"
    if len(sys.argv) > 1:
        version_file = sys.argv[1]

    # Resolve relative path to absolute path based on repo root
    # This script is expected to be run from the repo root or with an absolute path
    rev_version(version_file)
