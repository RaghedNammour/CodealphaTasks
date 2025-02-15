import os

# Bad practice: Hardcoded credentials
USERNAME = "admin"
PASSWORD = "123456"

def insecure_function():
    os.system("rm -rf /")  # Dangerous command execution
