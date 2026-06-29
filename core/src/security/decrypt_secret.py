import sys
import os
from encryption import hub_encryption

def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt_secret.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            print(hub_encryption.decrypt(content))
    except Exception as e:
        print(f"Error decrypting secret: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
