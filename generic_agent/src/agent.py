import asyncio
import json
import uuid
import time
import websockets
import logging
import os
import subprocess
from typing import Dict, Any
from core.src.messaging.control_plane import BaseControlPlane
from core.src.base_spoke import BaseSpoke

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GenericAgent")

class AgentModule(BaseSpoke):
    """
    The core module of the generic agent.
    Provides capabilities to execute shell commands and provision other modules.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if command_type == "EXECUTE_COMMAND":
            cmd = data.get("command")
            if not cmd:
                return {"status": "ERROR", "message": "Missing command"}

            logger.info(f"Executing command: {cmd}")
            try:
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                return {
                    "status": "SUCCESS" if process.returncode == 0 else "ERROR",
                    "stdout": stdout.decode().strip(),
                    "stderr": stderr.decode().strip(),
                    "exit_code": process.returncode
                }
            except Exception as e:
                logger.error(f"Command execution failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        if command_type == "PROVISION_MODULE":
            module_id = data.get("module_id")
            repo_url = data.get("repo_url")
            hub_url = data.get("hub_url")
            spoke_id = data.get("spoke_id")
            secret = data.get("secret")
            hub_secret = data.get("hub_secret")

            if not all([module_id, repo_url]):
                return {"status": "ERROR", "message": "Missing module_id or repo_url"}

            logger.info(f"Provisioning module {module_id} from {repo_url}...")

            install_dir = f"/opt/lm/{module_id}"
            try:
                # 1. Clone the repository
                if os.path.exists(install_dir):
                    subprocess.run(["rm", "-rf", install_dir], check=True)

                subprocess.run(["git", "clone", repo_url, install_dir], check=True)

                # 2. Run the installation script
                install_script = os.path.join(install_dir, "install.sh")
                if not os.path.exists(install_script):
                    # Try common variations
                    potential_scripts = [
                        os.path.join(install_dir, f"install_{module_id}.sh"),
                        os.path.join(install_dir, "setup.sh")
                    ]
                    for s in potential_scripts:
                        if os.path.exists(s):
                            install_script = s
                            break
                    else:
                        return {"status": "ERROR", "message": f"Installation script not found in {install_dir}"}

                subprocess.run(["chmod", "+x", install_script], check=True)

                # Prepare arguments for the install script
                cmd = [
                    "bash", install_script,
                    "--hub", hub_url,
                    "--id", spoke_id,
                    "--secret", secret
                ]
                if hub_secret:
                    cmd.extend(["--hub-secret", hub_secret])

                # We run this in the background or wait for it?
                # Since we want to know it worked, let's run it and wait.
                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode == 0:
                    return {"status": "SUCCESS", "message": f"Module {module_id} provisioned successfully", "stdout": result.stdout}
                else:
                    return {"status": "ERROR", "message": f"Install script failed: {result.stderr}", "stdout": result.stdout}

            except Exception as e:
                logger.error(f"Provisioning failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        return {"status": "ONLINE", "role": "generic-agent"}

class GenericAgentControlPlane(BaseControlPlane):
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)

        # The agent is its own module
        self.register_module("agent", AgentModule(spoke_id, {}))

    async def run(self):
        logger.info(f"Generic Agent starting... Connected to {self.hub_url}")
        await super().run()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--hub-secret")
    parser.add_argument("--hub", required=True)
    args = parser.parse_args()

    cp = GenericAgentControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
