import paramiko
import os
from dotenv import load_dotenv

load_dotenv()

class SSHClient:
    def __init__(self):
        self.host = os.getenv("SSH_HOSTNAME")
        self.user = os.getenv("SSH_USER")
        self.password = os.getenv("SSH_PASSWD")
        self.client = None

    def connect(self):
        if self.client is None:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.user, password=self.password)

    def run(self, command):
        self.connect()
        stdin, stdout, stderr = self.client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        return output if output else error or "Command executed successfully."

ssh = SSHClient()
def ssh_node(state):
    output = ssh.run(state["command"])
    return {"output": output}
