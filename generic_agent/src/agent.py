import asyncio
import json
import uuid
import time
import websockets
import logging
import os
import subprocess
from typing import Dict, Any, Optional, Optional
from core.src.messaging.control_plane import BaseControlPlane
from core.src.base_spoke import BaseSpoke

# Setup logging to both console and file
def get_log_path():
    primary = "/var/log/generic-agent.log"
    try:
        # Try to see if we can write to /var/log
        with open(primary, "a") as f:
            pass
        return primary
    except Exception:
        # Fallback to local logs directory
        local_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(local_dir, exist_ok=True)
        return os.path.join(local_dir, "generic-agent.log")

log_file = get_log_path()
logger.info(f"Logging to: {log_file}")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("GenericAgent")

def get_machine_id() -> str:
    """Generates a unique ID for the agent based on the machine ID or a random UUID."""
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id", "r") as f:
                mid = f.read().strip()
                if mid:
                    return f"hw-{mid[:12]}"
        if os.path.exists("/var/lib/dbus/machine-id"):
            with open("/var/lib/dbus/machine-id", "r") as f:
                mid = f.read().strip()
                if mid:
                    return f"hw-{mid[:12]}"
    except Exception as e:
        logger.debug(f"Could not read machine-id: {e}")

    # Fallback to a persisted random ID
    id_file = "/etc/lm-agent-id"
    if os.path.exists(id_file):
        with open(id_file, "r") as f:
            return f.read().strip()

    new_id = f"agent-{str(uuid.uuid4())[:8]}"
    try:
        with open(id_file, "w") as f:
            f.write(new_id)
    except Exception as e:
        logger.warning(f"Could not persist agent ID: {e}")

    return new_id

def get_vm_uuid() -> Optional[str]:
    """Retrieves the SMBIOS UUID, which can be used by the Hub to identify the Proxmox VMID."""
    try:
        if os.path.exists("/sys/class/dmi/id/product_uuid"):
            with open("/sys/class/dmi/id/product_uuid", "r") as f:
                return f.read().strip()
    except Exception as e:
        logger.debug(f"Could not read product_uuid: {e}")
    return None

class AgentModule(BaseSpoke):
    """
    The core module of the generic agent.
    Provides capabilities to execute shell commands and provision other modules.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if command_type == "SET_LOG_LEVEL":
            enabled = data.get("enabled", False)
            level = logging.DEBUG if enabled else logging.INFO
            logging.getLogger().setLevel(level)
            logger.info(f"Log level set to {logging.getLevelName(level)}")
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

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
    parser.add_argument("--id") # Now optional
    parser.add_argument("--secret") # Now optional to support secret-less bootstrap
    parser.add_argument("--hub-secret")
    parser.add_argument("--hub", required=True)
    args = parser.parse_args()

    # Use provided ID or generate one automatically
    spoke_id = args.id or get_machine_id()
    logger.info(f"Starting agent with spoke_id: {spoke_id}")

    cp = GenericAgentControlPlane(spoke_id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
