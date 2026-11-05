"""Command-line helper that decrypts a hub-encrypted secret file and prints the plaintext.

Usage: ``python decrypt_secret.py <file_path>``. Intended for operators who need to read
a secret that the hub stored encrypted on disk (e.g. while debugging a deployment).
"""
# sys gives access to the command-line arguments, stderr and the process exit code.
import sys
# The hub's shared encryption helper that knows the active Fernet key(s).
from encryption import hub_encryption

def main():
    """Decrypt the file named on the command line and print the result to stdout."""
    # Without a file path there is nothing to decrypt, so print usage and exit with an error.
    if len(sys.argv) < 2:
        print("Usage: python decrypt_secret.py <file_path>")
        sys.exit(1)

    # The first command-line argument is the path of the encrypted file.
    file_path = sys.argv[1]
    # Read the raw encrypted bytes (binary mode, since ciphertext is bytes) and decrypt them.
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            print(hub_encryption.decrypt(content))
    # Any failure (missing file, wrong key, corrupt data) is reported on stderr with exit 1
    # so scripts calling this tool can detect the error.
    except Exception as e:
        print(f"Error decrypting secret: {e}", file=sys.stderr)
        sys.exit(1)

# Only run main() when executed as a script, not when imported.
if __name__ == "__main__":
    main()
