"""Bump the minor number in a "Major.Minor" VERSION file.

The minor part keeps its digit width (e.g. 1.09 -> 1.10). When it would need more
digits than it has (1.99 -> 2.00), the major number is bumped and minor resets to 0.
Usage: python3 rev.py [path/to/VERSION]   (defaults to ./VERSION)
"""
# Read command-line arguments and exit with an error code on failure.
import sys
# Check that the version file exists before reading it.
import os

def rev_version(version_file):
    """Increment the version stored in version_file, write it back, and return the new string.

    Exits the process with status 1 if the file is missing or not in Major.Minor format.
    """
    # A missing file is a fatal usage error for this tool.
    if not os.path.exists(version_file):
        print(f"Error: Version file {version_file} not found.")
        sys.exit(1)

    # Read the current version string, trimming any trailing newline.
    with open(version_file, "r") as f:
        current_version = f.read().strip()

    # Any parse problem (bad format, non-numeric parts) is reported and treated as fatal.
    try:
        # Split "1.23" into ["1", "23"].
        parts = current_version.split('.')
        # Reject anything that is not exactly two dot-separated parts.
        if len(parts) != 2:
            raise ValueError("Version must be in Major.Minor format")

        # Convert major to a number; keep the minor text so we know its digit width.
        major = int(parts[0])
        minor_str = parts[1]
        minor = int(minor_str)

        # Move to the next minor version.
        minor += 1
        if minor >= 10 ** len(minor_str): # Simple rule: if minor overflows its current digit count, bump major and reset minor
            # Minor overflowed its digit width, so roll over to the next major version.
            major += 1
            minor = 0

        # Pad minor back to its original width, e.g. 5 -> "05" when it had two digits.
        # Preserve leading zeros
        new_minor_str = str(minor).zfill(len(minor_str))
        new_version = f"{major}.{new_minor_str}"

        # Overwrite the version file with the new version (no trailing newline, as before).
        with open(version_file, "w") as f:
            f.write(new_version)

        # Report the change for the person or CI log running the script.
        print(f"Version bumped: {current_version} -> {new_version}")
        return new_version
    # Any error above: print why and exit non-zero so the build stops.
    except Exception as e:
        print(f"Error parsing version: {e}")
        sys.exit(1)

# Run only when invoked as a script.
if __name__ == "__main__":
    # Default to root VERSION file
    version_file = "VERSION"
    # An explicit path on the command line overrides the default VERSION file.
    if len(sys.argv) > 1:
        version_file = sys.argv[1]

    # Resolve relative path to absolute path based on repo root
    # This script is expected to be run from the repo root or with an absolute path
    rev_version(version_file)
