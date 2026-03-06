"""
ThreatSense — Binary Analyzer Module
======================================
Analyzes binary files (executables, DLLs, unknown binaries) for
suspicious imports, entropy anomalies, IOCs, and PE header metadata.

Usage by main.py:
    from analyzer import analyze_binary
    result = analyze_binary(file_bytes, filename)

Returns a dict matching the ThreatSense pipeline contract.
"""

import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Any

# Attempt to import pefile — gracefully degrade if unavailable
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ---------------------------------------------------------------------------
#  Constants — Dangerous Windows API imports and their risk scores
# ---------------------------------------------------------------------------

DANGEROUS_IMPORTS = {
    # Process injection — classic malware technique to hide in trusted processes
    "VirtualAllocEx":       ("Process Injection",  30),
    "WriteProcessMemory":   ("Process Injection",  30),
    "CreateRemoteThread":   ("Process Injection",  35),
    "NtWriteVirtualMemory": ("Process Injection",  30),
    "RtlCreateUserThread":  ("Process Injection",  30),
    "QueueUserAPC":         ("Process Injection",  25),

    # Anti-analysis — detects debuggers and sandboxes
    "IsDebuggerPresent":    ("Anti-Analysis",      20),
    "CheckRemoteDebuggerPresent": ("Anti-Analysis", 20),
    "NtQueryInformationProcess":  ("Anti-Analysis", 15),
    "GetTickCount":         ("Anti-Analysis",      10),
    "OutputDebugStringA":   ("Anti-Analysis",      10),

    # Dropper / downloader — fetches payloads from the internet
    "URLDownloadToFileA":   ("Dropper",            35),
    "URLDownloadToFileW":   ("Dropper",            35),
    "InternetOpenA":        ("Network",            15),
    "InternetOpenW":        ("Network",            15),
    "InternetOpenUrlA":     ("Network",            20),
    "InternetOpenUrlW":     ("Network",            20),
    "HttpOpenRequestA":     ("Network",            15),
    "HttpSendRequestA":     ("Network",            15),
    "WSAStartup":           ("Network",            10),
    "connect":              ("Network",            15),
    "send":                 ("Network",            10),
    "recv":                 ("Network",            10),

    # Persistence — survives reboot
    "RegSetValueExA":       ("Persistence",        20),
    "RegSetValueExW":       ("Persistence",        20),
    "RegCreateKeyExA":      ("Persistence",        15),
    "CreateServiceA":       ("Persistence",        30),
    "CreateServiceW":       ("Persistence",        30),

    # Keylogging / spyware
    "SetWindowsHookExA":    ("Keylogging",         35),
    "SetWindowsHookExW":    ("Keylogging",         35),
    "GetAsyncKeyState":     ("Keylogging",         30),
    "GetKeyState":          ("Keylogging",         20),

    # Ransomware / encryption
    "CryptEncrypt":         ("Ransomware",         25),
    "CryptDecrypt":         ("Ransomware",         15),
    "CryptAcquireContextA": ("Ransomware",         15),
    "CryptGenKey":          ("Ransomware",         15),

    # Code execution
    "WinExec":              ("Code Execution",     25),
    "ShellExecuteA":        ("Code Execution",     20),
    "ShellExecuteW":        ("Code Execution",     20),
    "CreateProcessA":       ("Code Execution",     15),
    "CreateProcessW":       ("Code Execution",     15),
    "system":               ("Code Execution",     20),

    # Memory manipulation
    "VirtualProtect":       ("Memory Manipulation", 20),
    "VirtualAlloc":         ("Memory Manipulation", 10),
    "HeapCreate":           ("Memory Manipulation",  5),

    # Token / privilege escalation
    "AdjustTokenPrivileges": ("Privilege Escalation", 25),
    "OpenProcessToken":      ("Privilege Escalation", 15),
    "LookupPrivilegeValueA": ("Privilege Escalation", 10),

    # File operations (anti-forensics)
    "DeleteFileA":          ("Anti-Forensics",     10),
    "DeleteFileW":          ("Anti-Forensics",     10),
    "MoveFileExA":          ("Anti-Forensics",     10),
}


# Magic bytes → file type mapping
MAGIC_BYTES = {
    b"MZ":                       "Windows PE Executable",
    b"\x7fELF":                  "Linux ELF Executable",
    b"\xfe\xed\xfa\xce":        "macOS Mach-O (32-bit)",
    b"\xfe\xed\xfa\xcf":        "macOS Mach-O (64-bit)",
    b"\xca\xfe\xba\xbe":        "macOS Universal Binary / Java Class",
    b"PK":                       "ZIP Archive (possibly JAR/APK/DOCX)",
    b"\x1f\x8b":                 "GZIP Compressed",
    b"Rar!":                     "RAR Archive",
    b"\x89PNG":                  "PNG Image",
    b"\xff\xd8\xff":             "JPEG Image",
    b"GIF8":                     "GIF Image",
    b"%PDF":                     "PDF Document",
    b"\xd0\xcf\x11\xe0":        "Microsoft OLE2 (DOC/XLS/PPT)",
}

# IOC regex patterns (reuse same patterns as script_analyzer for consistency)
RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw|club|"
    r"online|site|tech|space|pro|dev|app|link|click|work|win|"
    r"download|stream|gdn|racing|review|date|trade|bid|loan|"
    r"party|science|cricket|accountant|faith|zip|mov|"
    r"co|me|in|de|fr|br|uk|su|to|ws|ly|gl|ga|cf|gq|ml)\b",
    re.IGNORECASE,
)
RE_URL = re.compile(r"https?://[^\s\"'<>\)\]\},;]+", re.IGNORECASE)
RE_REGISTRY = re.compile(r"HKEY_[A-Z_]+(?:\\{1,2}[A-Za-z0-9_ \-\.]+)+", re.IGNORECASE)
RE_WINPATH = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>\|\*\?:]+\\)*[^\s\"'<>\|\*\?:]+")

# Common benign domains to filter from IOCs
BENIGN_DOMAINS = {
    "google.com", "gmail.com", "outlook.com", "microsoft.com",
    "yahoo.com", "github.com", "stackoverflow.com", "python.org",
    "npmjs.com", "nodejs.org", "w3.org", "schema.org",
    "mozilla.org", "apache.org", "example.com", "localhost",
    "windows.com", "windowsupdate.com", "verisign.com",
    "digicert.com", "symantec.com", "globalsign.com",
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
        return "Low — likely plain text"
    if entropy < 6.0:
        return "Normal — typical executable"
    if entropy < 7.2:
        return "Elevated — possibly compressed"
    if entropy < 7.8:
        return "HIGH — likely encrypted or packed"
    return "CRITICAL — almost certainly packed malware"


# ---------------------------------------------------------------------------
#  String extraction
# ---------------------------------------------------------------------------

def _extract_strings(data: bytes, min_length: int = 5) -> list:
    """
    Extract all sequences of printable ASCII characters of at least
    *min_length* from raw bytes.  Also attempts UTF-16LE (Windows wide
    string) extraction for strings malware stores in native Windows format.
    This catches hardcoded IPs, domains, error messages, and other
    artefacts the malware author left behind.
    """
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    raw = re.findall(pattern, data)
    strings = []
    seen = set()
    for s in raw:
        try:
            decoded = s.decode("ascii")
            if decoded not in seen:
                seen.add(decoded)
                strings.append(decoded)
        except Exception:
            continue

    # --- UTF-16LE wide strings (common in Windows PE binaries) ---
    # Pattern: printable ASCII bytes interleaved with null bytes
    wide_pattern = rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    wide_matches = re.findall(wide_pattern, data)
    for wm in wide_matches:
        try:
            decoded = wm.decode("utf-16-le")
            if decoded not in seen and len(decoded) >= min_length:
                seen.add(decoded)
                strings.append(decoded)
        except Exception:
            continue

    return strings


# ---------------------------------------------------------------------------
#  IOC extraction from strings
# ---------------------------------------------------------------------------

def _extract_ips(text: str) -> list:
    """Extract IP addresses, filtering common false positives."""
    raw = set(RE_IP.findall(text))
    filtered = set()
    for ip in raw:
        octets = ip.split(".")
        if ip.startswith("0.") or ip.startswith("127."):
            continue
        if ip.startswith("255.") or ip == "0.0.0.0":
            continue
        if all(o == "0" for o in octets[1:]):
            continue
        # Filter out version-like strings (e.g. 5.1.2600.0)
        # by checking if octets are in the valid range
        try:
            if all(0 <= int(o) <= 255 for o in octets):
                filtered.add(ip)
        except ValueError:
            continue
    return sorted(filtered)


def _extract_domains(text: str) -> list:
    """Extract domains, filtering benign ones."""
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
    filtered = set()
    for p in raw:
        lower = p.lower()
        if lower in ("c:\\", "c:\\windows", "c:\\users"):
            continue
        filtered.add(p)
    return sorted(filtered)


def _extract_iocs_from_strings(strings: list) -> dict:
    """Run all IOC extraction on the joined strings."""
    combined = "\n".join(strings)
    return {
        "ips":           _extract_ips(combined),
        "domains":       _extract_domains(combined),
        "urls":          _extract_urls(combined),
        "registry_keys": _extract_registry_keys(combined),
        "file_paths":    _extract_file_paths(combined),
    }


# ---------------------------------------------------------------------------
#  File type detection via magic bytes
# ---------------------------------------------------------------------------

def _detect_file_type(data: bytes, filename: str) -> tuple:
    """
    Detect real file type from magic bytes.
    Falls back to extension-based guess if magic bytes are unknown.

    Returns
    -------
    tuple of (file_type: str, mismatch_warning: str or "")
        mismatch_warning is non-empty when the extension lies about the
        real type (e.g. .pdf with MZ bytes). This is an immediate red flag.
    """
    magic_type = None
    for magic, ftype in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            magic_type = ftype
            break

    # Determine extension-based type
    ext = ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()

    ext_map = {
        "exe": "Windows Executable (by extension)",
        "dll": "Windows DLL (by extension)",
        "sys": "Windows Driver (by extension)",
        "bin": "Binary File",
        "dat": "Data File",
        "so":  "Linux Shared Object (by extension)",
        "dylib": "macOS Dynamic Library (by extension)",
    }

    # Check for mismatch between extension and magic bytes
    mismatch = ""
    if magic_type:
        # Map extensions that should match certain magic types
        ext_to_expected_magic = {
            "pdf": "PDF Document",
            "png": "PNG Image",
            "jpg": "JPEG Image", "jpeg": "JPEG Image",
            "gif": "GIF Image",
            "doc": "Microsoft OLE2 (DOC/XLS/PPT)",
            "xls": "Microsoft OLE2 (DOC/XLS/PPT)",
            "zip": "ZIP Archive (possibly JAR/APK/DOCX)",
        }
        expected = ext_to_expected_magic.get(ext)
        if expected and expected != magic_type:
            mismatch = (
                f"EXTENSION MISMATCH: File has .{ext} extension but magic bytes "
                f"indicate {magic_type}. Likely a disguised executable."
            )
        return magic_type, mismatch

    return ext_map.get(ext, "Unknown Binary"), mismatch


# ---------------------------------------------------------------------------
#  PE header analysis
# ---------------------------------------------------------------------------

def _analyze_pe(data: bytes) -> dict:
    """
    Parse PE (Portable Executable) headers without executing the file.
    Extracts: compile timestamp, section info, dangerous imports.
    Returns a dict with PE-specific findings.
    """
    result = {
        "is_pe": True,
        "compile_timestamp": "",
        "compile_timestamp_suspicious": False,
        "sections": [],
        "dangerous_imports": [],
        "all_imports": [],
        "import_risk_score": 0,
        "pe_warnings": [],
    }

    if not PEFILE_AVAILABLE:
        result["pe_warnings"].append("pefile library not installed — PE analysis limited")
        result["is_pe"] = True  # We know it's MZ, just can't parse deeply
        return result

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        result["pe_warnings"].append(f"PE parse error: {str(e)}")
        return result
    except Exception as e:
        result["pe_warnings"].append(f"Unexpected PE error: {str(e)}")
        return result

    # --- Compile timestamp ---
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        result["compile_timestamp"] = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        now = datetime.now(tz=timezone.utc)
        # Suspicious if timestamp is before 2000 or more than 1 year in the future
        if compile_dt.year < 2000 or compile_dt > now.replace(year=now.year + 1):
            result["compile_timestamp_suspicious"] = True
            result["pe_warnings"].append(
                f"Suspicious compile timestamp: {result['compile_timestamp']} "
                f"— likely forged (dated {'far in the past' if compile_dt.year < 2000 else 'in the future'})"
            )
    except Exception:
        result["compile_timestamp"] = "Could not parse"

    # --- Section analysis ---
    try:
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            sec_entropy = section.get_entropy()
            sec_info = {
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(sec_entropy, 4),
            }
            # Flag high-entropy sections specifically
            if sec_entropy > 7.2:
                sec_info["suspicious"] = True
                sec_info["note"] = "HIGH entropy — likely packed/encrypted"
            result["sections"].append(sec_info)
    except Exception:
        pass

    # --- Import table analysis ---
    total_risk = 0
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="replace")
                        result["all_imports"].append(f"{dll_name}:{func_name}")

                        if func_name in DANGEROUS_IMPORTS:
                            category, score = DANGEROUS_IMPORTS[func_name]
                            result["dangerous_imports"].append({
                                "name": func_name,
                                "dll": dll_name,
                                "category": category,
                                "score": score,
                            })
                            total_risk += score
    except Exception:
        result["pe_warnings"].append("Could not parse import table")

    result["import_risk_score"] = min(total_risk, 100)

    # Sort dangerous imports by score descending
    result["dangerous_imports"].sort(key=lambda x: x["score"], reverse=True)

    try:
        pe.close()
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
#  Interesting strings — surface the most suspicious ones
# ---------------------------------------------------------------------------

def _select_interesting_strings(all_strings: list, iocs: dict, max_count: int = 30) -> list:
    """
    From all extracted strings, pick the most interesting/suspicious ones.
    Surfaces: URLs, IPs, registry keys, file paths, error messages, API names.
    """
    interesting = []
    seen = set()

    # Add IOC strings with type labels
    for ip in iocs.get("ips", []):
        if ip not in seen:
            interesting.append({"value": ip, "type": "IP Address"})
            seen.add(ip)

    for url in iocs.get("urls", []):
        if url not in seen:
            interesting.append({"value": url, "type": "URL"})
            seen.add(url)

    for domain in iocs.get("domains", []):
        if domain not in seen:
            interesting.append({"value": domain, "type": "Domain"})
            seen.add(domain)

    for reg_key in iocs.get("registry_keys", []):
        if reg_key not in seen:
            interesting.append({"value": reg_key, "type": "Registry Key"})
            seen.add(reg_key)

    for fpath in iocs.get("file_paths", []):
        if fpath not in seen:
            interesting.append({"value": fpath, "type": "File Path"})
            seen.add(fpath)

    # Add other suspicious-looking strings
    suspicious_keywords = [
        "password", "passwd", "credential", "token", "secret",
        "cmd.exe", "powershell", "rundll32", "regsvr32",
        "backdoor", "payload", "exploit", "inject", "hook",
        "malware", "trojan", "virus", "ransom", "encrypt",
        "admin", "root", "shell", "reverse",
    ]

    for s in all_strings:
        if len(interesting) >= max_count:
            break
        if s in seen:
            continue
        lower = s.lower()
        for kw in suspicious_keywords:
            if kw in lower:
                interesting.append({"value": s[:200], "type": "Suspicious String"})
                seen.add(s)
                break

    # Fill remaining slots with the longest unique strings (likely meaningful)
    remaining = sorted(
        [s for s in all_strings if s not in seen and len(s) > 10],
        key=len,
        reverse=True,
    )
    for s in remaining:
        if len(interesting) >= max_count:
            break
        interesting.append({"value": s[:200], "type": "Extracted String"})
        seen.add(s)

    return interesting[:max_count]


# ---------------------------------------------------------------------------
#  Risk score calculation
# ---------------------------------------------------------------------------

def _calculate_risk_score(
    entropy: float,
    import_risk_score: int,
    iocs: dict,
    pe_result: dict,
    is_pe: bool,
    file_type_mismatch: bool = False,
    size_bytes: int = 0,
) -> int:
    """
    Composite risk score 0–100 from all binary analysis signals.
    """
    score = 0

    # Entropy contribution (0-30)
    if entropy >= 7.8:
        score += 30
    elif entropy >= 7.2:
        score += 25
    elif entropy >= 6.0:
        score += 10

    # Import risk contribution (0-40, scaled)
    if is_pe:
        score += min(import_risk_score * 40 // 100, 40)

    # IOC contribution (0-15)
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs > 10:
        score += 15
    elif total_iocs > 5:
        score += 10
    elif total_iocs > 0:
        score += 5

    # Suspicious compile timestamp (0-10)
    if pe_result.get("compile_timestamp_suspicious"):
        score += 10

    # High-entropy sections (0-5)
    for sec in pe_result.get("sections", []):
        if sec.get("suspicious"):
            score += 5
            break

    # File type mismatch (extension vs magic bytes) — strong red flag (0-15)
    if file_type_mismatch:
        score += 15

    # Size anomaly: PE file under 5KB is suspicious (probably dropper stub)
    if is_pe and 0 < size_bytes < 5120:
        score += 5

    return min(score, 100)


# ---------------------------------------------------------------------------
#  Main public function
# ---------------------------------------------------------------------------

def analyze_binary(file_bytes: bytes, filename: str = "unknown.bin") -> dict:
    """
    Analyze a binary file and return a structured findings dict
    compatible with the ThreatSense analysis pipeline.

    Parameters
    ----------
    file_bytes : bytes
        Raw bytes of the binary file.
    filename : str
        Original uploaded filename (used for type detection).

    Returns
    -------
    dict
        Structured analysis result matching the pipeline contract.
    """
    # Graceful handling of None/empty input
    if file_bytes is None:
        file_bytes = b""

    try:
        return _analyze_binary_impl(file_bytes, filename)
    except Exception as e:
        # Absolute fallback — never crash the pipeline
        hashes = _compute_hashes(file_bytes) if file_bytes else {"md5": "", "sha1": "", "sha256": ""}
        return {
            "filename": filename,
            "input_type": "binary",
            "file_type": "Unknown Binary (analysis error)",
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "size_bytes": len(file_bytes),
            "entropy": 0.0,
            "entropy_verdict": "Analysis failed",
            "is_pe": False,
            "compile_timestamp": "",
            "compile_timestamp_suspicious": False,
            "dangerous_imports": [],
            "all_imports": [],
            "import_risk_score": 0,
            "sections": [],
            "pe_warnings": [f"Analysis error: {str(e)}"],
            "iocs": {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []},
            "interesting_strings": [],
            "risk_score": 0,
            "verdict": f"Analysis failed: {str(e)}",
        }


def _analyze_binary_impl(file_bytes: bytes, filename: str) -> dict:
    """Core binary analysis implementation."""

    # --- Step 1: Compute hashes ---
    hashes = _compute_hashes(file_bytes)
    size_bytes = len(file_bytes)

    # --- Step 2: Calculate entropy ---
    entropy = _calculate_entropy(file_bytes)
    ent_verdict = _entropy_verdict(entropy)

    # --- Step 3: Detect file type from magic bytes (now returns mismatch) ---
    file_type, type_mismatch = _detect_file_type(file_bytes, filename)

    # --- Step 3b: Check for EICAR test string ---
    eicar_detected = False
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in file_bytes:
        eicar_detected = True

    # --- Step 4: Extract readable strings (ASCII + UTF-16LE) ---
    all_strings = _extract_strings(file_bytes, min_length=5)

    # --- Step 5: Extract IOCs from strings ---
    iocs = _extract_iocs_from_strings(all_strings)

    # --- Step 6: PE header analysis (only if MZ signature) ---
    is_pe = len(file_bytes) >= 2 and file_bytes[:2] == b"MZ"
    pe_result = {}

    if is_pe:
        pe_result = _analyze_pe(file_bytes)
    else:
        pe_result = {
            "is_pe": False,
            "compile_timestamp": "",
            "compile_timestamp_suspicious": False,
            "sections": [],
            "dangerous_imports": [],
            "all_imports": [],
            "import_risk_score": 0,
            "pe_warnings": [],
        }

    # Add type mismatch to pe_warnings if present
    if type_mismatch:
        pe_result.setdefault("pe_warnings", []).append(type_mismatch)

    # --- Step 7: Calculate composite risk score ---
    risk_score = _calculate_risk_score(
        entropy, pe_result.get("import_risk_score", 0),
        iocs, pe_result, is_pe,
        file_type_mismatch=bool(type_mismatch),
        size_bytes=size_bytes,
    )

    # --- Step 8: Select interesting strings ---
    interesting_strings = _select_interesting_strings(all_strings, iocs)

    # --- Step 9: Generate human-readable verdict ---
    verdict = _generate_verdict(
        file_type, entropy, ent_verdict, risk_score,
        pe_result, iocs, is_pe,
    )

    # Append type mismatch alert to verdict
    if type_mismatch:
        verdict += f" ⚠ {type_mismatch}"

    # --- Step 10: Build and return result ---
    return {
        "filename": filename,
        "input_type": "binary",
        "file_type": file_type,
        "file_type_mismatch": type_mismatch,
        "eicar_detected": eicar_detected,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "size_bytes": size_bytes,
        "entropy": entropy,
        "entropy_verdict": ent_verdict,
        "is_pe": pe_result.get("is_pe", is_pe),
        "compile_timestamp": pe_result.get("compile_timestamp", ""),
        "compile_timestamp_suspicious": pe_result.get("compile_timestamp_suspicious", False),
        "dangerous_imports": pe_result.get("dangerous_imports", []),
        "all_imports": pe_result.get("all_imports", []),
        "import_risk_score": pe_result.get("import_risk_score", 0),
        "sections": pe_result.get("sections", []),
        "pe_warnings": pe_result.get("pe_warnings", []),
        "iocs": iocs,
        "interesting_strings": interesting_strings,
        "risk_score": risk_score,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
#  Verdict generator
# ---------------------------------------------------------------------------

def _generate_verdict(
    file_type: str,
    entropy: float,
    entropy_verdict: str,
    risk_score: int,
    pe_result: dict,
    iocs: dict,
    is_pe: bool,
) -> str:
    """
    Generate a plain-English summary verdict for the binary.
    This pre-LLM verdict gives analysts immediate context.
    """
    parts = []

    # Severity label
    if risk_score >= 70:
        parts.append("CRITICAL RISK binary detected.")
    elif risk_score >= 50:
        parts.append("HIGH RISK binary detected.")
    elif risk_score >= 30:
        parts.append("MEDIUM RISK binary detected.")
    elif risk_score >= 10:
        parts.append("LOW RISK binary detected.")
    else:
        parts.append("MINIMAL RISK — binary appears benign.")

    # File type
    parts.append(f"File type: {file_type}.")

    # Entropy
    if entropy >= 7.2:
        parts.append(
            f"Entropy is {entropy:.2f} ({entropy_verdict}) — strongly suggests "
            "the binary is packed or encrypted to evade antivirus detection."
        )
    elif entropy >= 6.0:
        parts.append(
            f"Entropy is {entropy:.2f} ({entropy_verdict}) — may contain "
            "compressed or encoded sections."
        )

    # PE-specific verdicts
    if is_pe:
        dangerous = pe_result.get("dangerous_imports", [])
        if dangerous:
            # Group by category
            categories = {}
            for imp in dangerous:
                cat = imp.get("category", "Unknown")
                categories.setdefault(cat, []).append(imp["name"])

            cat_strs = [f"{cat} ({', '.join(funcs)})" for cat, funcs in categories.items()]
            parts.append(
                f"Found {len(dangerous)} dangerous API import(s) across categories: "
                + "; ".join(cat_strs) + "."
            )

        if pe_result.get("compile_timestamp_suspicious"):
            parts.append(
                f"Compile timestamp ({pe_result.get('compile_timestamp', 'unknown')}) "
                "appears forged — common malware anti-forensics technique."
            )

        # High-entropy sections
        suspicious_secs = [s["name"] for s in pe_result.get("sections", []) if s.get("suspicious")]
        if suspicious_secs:
            parts.append(
                f"Section(s) with suspiciously high entropy: {', '.join(suspicious_secs)} "
                "— likely packed/encrypted payload."
            )

    # IOCs
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs > 0:
        ioc_parts = []
        for key, label in [("ips", "IP"), ("domains", "domain"), ("urls", "URL"),
                           ("registry_keys", "registry key"), ("file_paths", "file path")]:
            count = len(iocs.get(key, []))
            if count > 0:
                ioc_parts.append(f"{count} {label}(s)")
        parts.append(f"Extracted IOCs: {', '.join(ioc_parts)}.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
#  Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    # Test 1: Simple text (should detect as non-PE, low risk)
    print("=== Test 1: Simple text file ===")
    test_data = b"Hello, this is a test file with an IP 193.42.11.23 and http://evil.ru/payload.exe inside."
    result = analyze_binary(test_data, "test.bin")
    print(f"  file_type:    {result['file_type']}")
    print(f"  is_pe:        {result['is_pe']}")
    print(f"  entropy:      {result['entropy']}")
    print(f"  risk_score:   {result['risk_score']}")
    print(f"  IPs found:    {result['iocs']['ips']}")
    print(f"  URLs found:   {result['iocs']['urls']}")
    print(f"  verdict:      {result['verdict'][:120]}...")
    assert result["input_type"] == "binary"
    assert result["is_pe"] is False
    assert "193.42.11.23" in result["iocs"]["ips"]
    print("  [PASS]")

    # Test 2: MZ header without valid PE (edge case)
    print("\n=== Test 2: Fake MZ header ===")
    fake_pe = b"MZ" + b"\x00" * 100
    result = analyze_binary(fake_pe, "fake.exe")
    print(f"  file_type:    {result['file_type']}")
    print(f"  is_pe:        {result['is_pe']}")
    print(f"  pe_warnings:  {result['pe_warnings']}")
    assert result["input_type"] == "binary"
    print("  [PASS]")

    # Test 3: Empty file
    print("\n=== Test 3: Empty file ===")
    result = analyze_binary(b"", "empty.bin")
    assert result["input_type"] == "binary"
    assert result["risk_score"] == 0
    print("  [PASS]")

    # Test 4: None input
    print("\n=== Test 4: None input ===")
    result = analyze_binary(None, "none.bin")
    assert result["input_type"] == "binary"
    print("  [PASS]")

    print("\n=== All binary analyzer tests passed ===")
