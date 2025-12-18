import paramiko
import os
from dotenv import load_dotenv
from src.utils.logger import get_logger
from src.utils.settings import llm

load_dotenv()

logger = get_logger(__name__)

class SSHClient:
    def __init__(self):
        logger.info("Entering SSHClient.__init__")
        self.host = os.getenv("SSH_HOSTNAME")
        self.user = os.getenv("SSH_USER")
        self.password = os.getenv("SSH_PASSWD")
        self.client = None

    def connect(self):
        logger.info("Entering SSHClient.connect")
        if self.client is None:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.info(f"Connecting to {self.host} as {self.user}")
            self.client.connect(self.host, username=self.user, password=self.password)
            logger.info("Connected to the server successfully")

    def run(self, command):
        logger.info(f"Entering SSHClient.run with command: {command[:50]}...")
        self.connect()
        logger.info(f"Executing command: {command}")
        stdin, stdout, stderr = self.client.exec_command(command)
        logger.info(f"SSHClient.run Command executed successfully")
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        logger.info(f"SSHClient.run output: {output}")
        logger.info(f"SSHClient.run error: {error}")
        return output if output else error or "Command executed successfully."

ssh = SSHClient()

def ssh_node(state):
    logger.info("Entering ssh_node")

    # Convert user input to command using LLM if command not already provided
    user_input = state.get("user_input", "")
    if not user_input:
        return {"output": "No command or user input provided."}
        
    logger.info("Converting user input to Linux command using LLM")
    prompt = f"User wants to: {user_input}. Decide what Linux command should be run and return only the command."
    command = llm.invoke(prompt).content.strip()
    
    if not command:
        return {"output": "Failed to generate ssh command from user input."}

    output = ssh.run(command)
    output = f"running `command: {command}`\nReceived `output:`\n{output}"
    return {"output": output, "command": command}

