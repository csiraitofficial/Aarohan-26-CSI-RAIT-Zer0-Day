import os
import re
import json
import requests

# ── Config ────────────────────────────────────────────────────────────────────
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL      = "llama3"          # change to "mistral" if needed
TIMEOUT    = 120               # seconds before we give up waiting

# ── Fallback returned when anything goes wrong ────────────────────────────────
FALLBACK = {
    "threat_classification": "UNKNOWN",
    "severity":              "UNKNOWN",
    "confidence":            0,
    "attack_techniques":     [],
    "behavioral_summary":    "Analysis could not be completed.",
    "executive_summary":     "LLM response could not be parsed. Manual review required.",
    "ioc_highlights":        [],
    "remediation":           ["Manually review the file with a senior analyst."],
    "analyst_notes":         ""
}

REQUIRED_FIELDS = [
    "threat_classification", "severity", "confidence",
    "attack_techniques", "behavioral_summary", "executive_summary",
    "ioc_highlights", "remediation", "analyst_notes"
]


# ── Step 1 : Build the prompt ─────────────────────────────────────────────────
def build_prompt(data: dict) -> str:

    # ── Artifact info ──────────────────────────────────────────────────────────
    filename   = data.get("filename",   "unknown")
    input_type = data.get("input_type", "unknown")
    size_bytes = data.get("size_bytes", "unknown")
    sha256     = data.get("sha256",     "unknown")

    # ── Entropy ────────────────────────────────────────────────────────────────
    entropy        = data.get("entropy",        "unknown")
    entropy_verdict= data.get("entropy_verdict","No interpretation available.")

    # ── Static analysis ────────────────────────────────────────────────────────
    static = data.get("static_analysis", {})

    if input_type == "binary":
        imports = static.get("dangerous_imports", [])
        import_lines = "\n".join(
            f"  - {i.get('name','?')} ({i.get('category','?')}): {i.get('description','?')}"
            for i in imports
        ) or "  None detected."
        import_risk  = static.get("import_risk_score", 0)
        static_block = f"""Dangerous API Imports Found:
{import_lines}
Import Risk Score: {import_risk}/100"""

    else:  # script
        language    = static.get("language",    "unknown")
        obfuscated  = static.get("obfuscation_detected", False)
        obf_line    = "Yes" if obfuscated else "No"
        decoded     = static.get("decoded_content", "")
        decoded_line= f"\nDecoded Payload: {decoded}" if obfuscated and decoded else ""

        func_calls  = static.get("dangerous_functions", [])
        func_lines  = "\n".join(
            f"  - {f.get('function','?')}: {f.get('reason','?')}"
            for f in func_calls
        ) or "  None detected."

        static_block = f"""Language: {language}
Obfuscation Detected: {obf_line}{decoded_line}
Dangerous Function Calls:
{func_lines}"""

    # ── IOCs ───────────────────────────────────────────────────────────────────
    iocs    = data.get("iocs", {})
    ips     = ", ".join(iocs.get("ips",     [])[:10]) or "None"
    domains = ", ".join(iocs.get("domains", [])[:10]) or "None"
    urls    = ", ".join(iocs.get("urls",    [])[:10]) or "None"

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    vt = data.get("virustotal", {})
    if vt.get("found"):
        malicious   = vt.get("malicious", 0)
        total       = vt.get("total",     0)
        threat_names= ", ".join(vt.get("threat_names", [])) or "N/A"
        vt_block    = f"""Detection Rate: {malicious}/{total} engines flagged as malicious
Threat Names: {threat_names}"""
    else:
        vt_block = "Not found in VirusTotal database — file may be novel or targeted."

    # ── Correlation ────────────────────────────────────────────────────────────
    corr = data.get("correlation", {})
    if corr.get("matches_found"):
        match_count   = corr.get("match_count", 0)
        incident_count= corr.get("incident_count", 0)
        corr_block    = f"WARNING: {match_count} IOCs from this file appeared in {incident_count} previous incidents."
    else:
        corr_block = "No matches found in incident history."

    # ── Assemble full prompt ───────────────────────────────────────────────────
    prompt = f"""You are a senior cybersecurity analyst with 15 years of experience.

=== ARTIFACT INFORMATION ===
Filename: {filename}
Type: {input_type}
Size: {size_bytes} bytes
SHA256: {sha256}

=== ENTROPY ANALYSIS ===
Score: {entropy}/8.0
Interpretation: {entropy_verdict}
Note: Scores above 7.2 indicate encrypted or packed content — a strong indicator of malware attempting to evade antivirus detection.

=== STATIC ANALYSIS ===
{static_block}

=== INDICATORS OF COMPROMISE ===
IP Addresses: {ips}
Domains: {domains}
URLs: {urls}

=== VIRUSTOTAL RESULT ===
{vt_block}

=== CORRELATION WITH PAST INCIDENTS ===
{corr_block}

=== YOUR TASK ===
Analyze ALL the above information together. Do not just list the findings — reason about what they mean in combination. A file with high entropy + process injection imports + unknown to VirusTotal is more suspicious than any single factor alone.

Respond ONLY with this exact JSON structure, no other text:
{{
  "threat_classification": "...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|BENIGN",
  "confidence": 0-100,
  "attack_techniques": ["..."],
  "behavioral_summary": "...",
  "executive_summary": "3-4 sentences plain English for a manager",
  "ioc_highlights": ["..."],
  "remediation": ["step 1", "step 2", ...],
  "analyst_notes": "..."
}}"""

    return prompt


# ── Step 2-7 : Call Ollama, parse, validate, return ───────────────────────────
def generate_report(analysis_data: dict) -> dict:

    # Step 1 — build prompt
    prompt = build_prompt(analysis_data)
    print("[ollama_client] Prompt built. Sending to Ollama...")

    # Step 2 — POST to Ollama
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":   MODEL,
                "prompt":  prompt,
                "stream":  False,
                "options": {
                    "temperature": 0.1,
                    "top_p":       0.9,
                    "num_predict": 800
                }
            },
            timeout=TIMEOUT
        )
        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        print("[ollama_client] ERROR: Cannot reach Ollama. Is it running?")
        fallback = FALLBACK.copy()
        fallback["analyst_notes"] = "Ollama unreachable. Start Ollama with: OLLAMA_HOST=0.0.0.0 ollama serve"
        return fallback

    except requests.exceptions.Timeout:
        print(f"[ollama_client] ERROR: Request timed out after {TIMEOUT}s.")
        fallback = FALLBACK.copy()
        fallback["analyst_notes"] = f"Request timed out after {TIMEOUT} seconds."
        return fallback

    except requests.exceptions.HTTPError as e:
        print(f"[ollama_client] ERROR: HTTP error — {e}")
        fallback = FALLBACK.copy()
        fallback["analyst_notes"] = f"HTTP error: {e}"
        return fallback

    # Step 3 — extract raw text from response
    raw_text = response.json().get("response", "")
    print("[ollama_client] Response received. Parsing...")

    # Step 4 — strip accidental markdown fences
    clean_text = re.sub(r"```json|```", "", raw_text).strip()

    # Step 5 — parse JSON
    try:
        parsed = json.loads(clean_text)

    except json.JSONDecodeError:
        print("[ollama_client] ERROR: Could not parse JSON from LLM response.")
        fallback = FALLBACK.copy()
        fallback["analyst_notes"] = f"Raw LLM output (unparseable):\n{raw_text[:500]}"
        return fallback

    # Step 6 — validate all required fields, add defaults if missing
    for field in REQUIRED_FIELDS:
        if field not in parsed:
            print(f"[ollama_client] WARNING: Missing field '{field}' — adding default.")
            parsed[field] = FALLBACK[field]

    # Ensure severity is one of the valid values
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN", "UNKNOWN"}
    if parsed["severity"] not in valid_severities:
        print(f"[ollama_client] WARNING: Invalid severity '{parsed['severity']}' — defaulting to UNKNOWN.")
        parsed["severity"] = "UNKNOWN"

    # Step 7 — return clean report
    print(f"[ollama_client] Report generated. Severity: {parsed['severity']} | Confidence: {parsed['confidence']}%")
    return parsed


# ── Quick local test ──────────────────────────────────────────────────────────
if __name__ == "__main__":

    # Fake analysis_data to test without Member 1
    test_data = {
        "filename":       "suspicious_update.exe",
        "input_type":     "binary",
        "size_bytes":     204800,
        "sha256":         "a3f5c2d1e4b7890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "entropy":        7.8,
        "entropy_verdict":"Very high — content is likely encrypted or packed.",
        "static_analysis": {
            "dangerous_imports": [
                {"name": "CreateRemoteThread", "category": "Process Injection",  "description": "Enables injecting code into other running processes"},
                {"name": "WriteProcessMemory", "category": "Memory Manipulation","description": "Writes arbitrary data into another process's memory"},
                {"name": "VirtualAllocEx",     "category": "Memory Allocation",  "description": "Allocates executable memory in a remote process"}
            ],
            "import_risk_score": 87
        },
        "iocs": {
            "ips":     ["192.168.1.105", "45.33.32.156"],
            "domains": ["evil-update.ru", "malware-cdn.xyz"],
            "urls":    ["http://evil-update.ru/payload.bin"]
        },
        "virustotal": {
            "found":        True,
            "malicious":    3,
            "total":        70,
            "threat_names": ["Trojan.GenericKD", "Backdoor.Agent"]
        },
        "correlation": {
            "matches_found":  True,
            "match_count":    2,
            "incident_count": 1
        }
    }

    report = generate_report(test_data)
    print("\n===== FINAL REPORT =====")
    print(json.dumps(report, indent=2))
