import asyncio
import os
import sys

# Add the hub directory to sys.path
sys.path.append('/Users/lbockenstedt/vscode/lm/hub/src')
# We also need the messaging, security, state packages if they are in the same directory
# Based on the imports in main.py:
# from messaging.protocol import ...
# from messaging.mailbox import ...
# from security.key_manager import ...
# from state.manager import ...
# from security.auth_manager import ...
# from api import run_api_server

# Let's see where those are.
# Looking at main.py imports:
# from messaging.protocol import Message ...
# These are likely in /Users/lbockenstedt/vscode/lm/hub/src/messaging, etc.
# But wait, the imports are 'from messaging.protocol', not 'from src.messaging.protocol'.
# This means /Users/lbockenstedt/vscode/lm/hub/src must be in PYTHONPATH.

try:
    from main import LabManagerHub
except ImportError:
    # Try adding the root as well
    sys.path.append('/Users/lbockenstedt/vscode/lm/hub/src')
    from main import LabManagerHub

async def test_version():
    hub = LabManagerHub()
    version = await hub.get_local_version()
    print(f"Local Version: {version}")

if __name__ == "__main__":
    asyncio.run(test_version())
