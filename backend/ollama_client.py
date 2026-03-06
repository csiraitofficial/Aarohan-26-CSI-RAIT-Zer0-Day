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

    # ── EICAR detection ───────────────────────────────────────────────────────
    eicar_detected = data.get("eicar_detected", False)

    # ── Analyzer verdict (pre-computed summary) ───────────────────────────────
    verdict = data.get("verdict", "")

    # ── Compound attack patterns (download-and-execute, reverse shells) ──────
    compound_patterns = data.get("compound_patterns", [])

    # ── Entropy ────────────────────────────────────────────────────────────────
    entropy        = data.get("entropy",        "unknown")
    entropy_verdict= data.get("entropy_verdict","No interpretation available.")

    # ── Static analysis (fields come flat from analyzer, not nested) ───────────
    if input_type == "binary":
        imports = data.get("dangerous_imports", [])
        import_lines = "\n".join(
            f"  - {i.get('name','?')} ({i.get('category','?')}, score: {i.get('score','?')})"
            for i in imports
        ) or "  None detected."
        import_risk  = data.get("import_risk_score", 0)
        compile_ts   = data.get("compile_timestamp", "")
        ts_line      = f"\nCompile Timestamp: {compile_ts}" if compile_ts else ""
        ts_suspicious= data.get("compile_timestamp_suspicious", False)
        if ts_suspicious:
            ts_line += " ⚠ SUSPICIOUS — likely forged"
        static_block = f"""Dangerous API Imports Found:
{import_lines}
Import Risk Score: {import_risk}/100{ts_line}"""

    else:  # script
        language    = data.get("language",    "unknown")
        obfuscated  = data.get("obfuscation_found", False)
        obf_line    = "Yes" if obfuscated else "No"

        # Build decoded payload summary from obfuscation_details list
        obf_details = data.get("obfuscation_details", [])
        decoded_line = ""
        if obfuscated and obf_details:
            decoded_parts = []
            for detail in obf_details[:3]:  # show top 3
                dec = detail.get("decoded", "") if isinstance(detail, dict) else str(detail)
                if dec:
                    decoded_parts.append(dec[:300])
            if decoded_parts:
                decoded_line = "\nDecoded Payload(s):\n" + "\n".join(f"  → {p}" for p in decoded_parts)

        func_calls  = data.get("dangerous_calls", [])
        func_lines  = "\n".join(
            f"  - {f.get('function','?')}: {f.get('reason','?')}"
            for f in func_calls
        ) or "  None detected."

        persistence = data.get("persistence_indicators", [])
        persist_line = ""
        if persistence:
            persist_line = "\nPersistence Indicators:\n" + "\n".join(f"  - {p}" for p in persistence)

        static_block = f"""Language: {language}
Obfuscation Detected: {obf_line}{decoded_line}
Dangerous Function Calls:
{func_lines}{persist_line}"""

    # ── Compound patterns ──────────────────────────────────────────────────────
    compound_block = ""
    if compound_patterns:
        cp_lines = []
        for cp in compound_patterns:
            cp_lines.append(f"  - [{cp.get('severity', 'HIGH')}] {cp.get('pattern', 'Unknown pattern')}")
        compound_block = "\nCompound Attack Patterns Detected:\n" + "\n".join(cp_lines)

    # ── IOCs ───────────────────────────────────────────────────────────────────
    iocs    = data.get("iocs", {})
    ips     = ", ".join(iocs.get("ips",     [])[:10]) or "None"
    domains = ", ".join(iocs.get("domains", [])[:10]) or "None"
    urls    = ", ".join(iocs.get("urls",    [])[:10]) or "None"

    # ── VirusTotal (main.py passes this as "vt_result") ───────────────────────
    vt = data.get("vt_result", {})
    if vt.get("known"):
        malicious   = vt.get("malicious", 0)
        total       = vt.get("total",     0)
        threat_names= ", ".join(vt.get("threat_names", [])) or "N/A"
        vt_block    = f"""Detection Rate: {malicious}/{total} engines flagged as malicious
Threat Names: {threat_names}"""
    elif vt.get("available"):
        vt_block = "Not found in VirusTotal database — file may be novel or targeted. Do not dismiss."
    else:
        vt_block = "VirusTotal lookup unavailable."

    # ── Correlation ────────────────────────────────────────────────────────────
    corr = data.get("correlation", {})
    if corr.get("matches_found"):
        match_count    = corr.get("match_count", 0)
        related        = corr.get("related_incidents", [])
        incident_count = len(related)
        campaign       = corr.get("campaign_flag", False)
        corr_block     = f"WARNING: {match_count} IOC(s) from this file appeared in {incident_count} previous incident(s)."
        if campaign:
            corr_block += " CAMPAIGN DETECTED — coordinated attack likely."
    else:
        corr_block = "No matches found in incident history."

    # ── Assemble full prompt ───────────────────────────────────────────────────
    prompt = f"""You are a senior cybersecurity incident analyst. Your job is to produce an ACCURATE, EVIDENCE-BASED threat assessment. You must NEVER fabricate, invent, or assume findings that are not directly supported by the data below.

=== CRITICAL RULES — READ BEFORE ANALYZING ===
1. ONLY report attack techniques, IOCs, and behaviors that are DIRECTLY evidenced in the data below.
2. If no dangerous imports are found, do NOT claim "Process Injection" or any import-based technique.
3. If no IOCs are extracted, do NOT invent IP addresses, domains, or URLs.
4. If entropy is low and no suspicious indicators exist, the file is most likely BENIGN.
5. "Unknown Binary" file type simply means the file format was not recognized — it does NOT imply maliciousness.
6. 0 VirusTotal detections with no other suspicious indicators = likely safe. Zero detections ALONE is not suspicious.
7. ABSENCE of evidence is NOT evidence of evasion. Do not claim a file is "evading detection" unless there is positive evidence of evasion techniques (obfuscation, packing, anti-analysis tricks).
8. If the file contains the EICAR test string, classify it as "EICAR Test File" with severity BENIGN or LOW.

=== SEVERITY CALIBRATION — USE THIS SCALE ===
- BENIGN: No suspicious indicators at all. Low entropy, no dangerous imports, no IOCs, 0 VT detections. Example: a plain text file, a normal document, null bytes, the EICAR test string.
- LOW: Minor suspicious indicators but no clear malicious intent. Example: a script with one unusual function call but no obfuscation, no IOCs, low VT detections.
- MEDIUM: Multiple moderate indicators present. Example: elevated entropy + a few suspicious imports, OR obfuscation detected but no known IOCs.
- HIGH: Strong evidence of malicious behavior. Example: high entropy + dangerous imports (process injection, credential theft) + extracted IOCs pointing to known C2 infrastructure.
- CRITICAL: Definitive malware with active threat indicators. Example: high VT detection rate + confirmed C2 communication IOCs + process injection imports + correlation with past campaigns.

=== ARTIFACT INFORMATION ===
Filename: {filename}
Type: {input_type}
Size: {size_bytes} bytes
SHA256: {sha256}
EICAR Test File Detected: {"YES — this is the standard antivirus test string, classify as BENIGN" if eicar_detected else "No"}

=== PRE-ANALYSIS VERDICT ===
{verdict or "No pre-analysis verdict available."}

=== ENTROPY ANALYSIS ===
Score: {entropy}/8.0
Interpretation: {entropy_verdict}

=== STATIC ANALYSIS ===
{static_block}{compound_block}

=== INDICATORS OF COMPROMISE ===
IP Addresses: {ips}
Domains: {domains}
URLs: {urls}

=== VIRUSTOTAL RESULT ===
{vt_block}

=== CORRELATION WITH PAST INCIDENTS ===
{corr_block}

=== YOUR TASK ===
Carefully review EVERY section above. Base your classification STRICTLY on what the data shows:
- Count the actual suspicious indicators present (not absent).
- If most sections show "None detected" or benign values, your severity MUST be BENIGN or LOW.
- Match your severity to the calibration scale above. Do NOT default to HIGH or CRITICAL without strong evidence.
- For attack_techniques, list ONLY techniques with direct evidence in the data. An empty list [] is correct when no techniques are evidenced.
- For ioc_highlights, list ONLY IOCs that were actually extracted above (not the file's own hash).

Respond ONLY with this exact JSON structure, no other text:
{{
  "threat_classification": "specific malware family OR 'Benign File' OR 'Suspicious' OR 'EICAR Test File' etc.",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|BENIGN",
  "confidence": 0-100,
  "attack_techniques": ["only techniques with DIRECT evidence, or empty list []"],
  "behavioral_summary": "technical analysis based strictly on the evidence above",
  "executive_summary": "3-4 sentences plain English for a manager",
  "ioc_highlights": ["only IOCs actually found in the data, or empty list []"],
  "remediation": ["step 1", "step 2"],
  "analyst_notes": "uncertainties and caveats"
}}"""

    return prompt


# ── Step 2-7 : Call Ollama, parse, validate, return ───────────────────────────
def generate_report(analysis_data: dict) -> dict:

    # Step 1 — build prompt
    prompt = build_prompt(analysis_data)
    print("[ollama_client] Prompt built. Sending to Ollama...")

    # Step 2 — POST to Ollama using /api/generate with format: "json"
    # CRITICAL: format:"json" constrains the grammar so the model MUST produce
    # valid JSON before emitting EOS. Without it, the model stops mid-JSON.
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":   MODEL,
                "prompt":  prompt,
                "stream":  False,
                "format":  "json",
                "options": {
                    "temperature": 0.1,
                    "top_p":       0.9,
                    "num_predict": 2048
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
    resp_data = response.json()
    raw_text = resp_data.get("response", "")
    eval_count = resp_data.get("eval_count", "?")
    print(f"[ollama_client] Response received ({len(raw_text)} chars, {eval_count} tokens). Parsing...")

    # Step 4 — strip accidental markdown fences
    clean_text = re.sub(r"```json|```", "", raw_text).strip()

    # Step 5 — extract JSON object from text
    # Llama3 often wraps JSON in conversational prose like "Here is the analysis:\n{...}\nI hope..."
    # We find the first '{' and match braces to extract just the JSON object.
    parsed = None
    json_start = clean_text.find('{')
    if json_start != -1:
        depth = 0
        json_end = -1
        for i in range(json_start, len(clean_text)):
            if clean_text[i] == '{':
                depth += 1
            elif clean_text[i] == '}':
                depth -= 1
                if depth == 0:
                    json_end = i + 1
                    break
        if json_end > json_start:
            json_str = clean_text[json_start:json_end]
            try:
                parsed = json.loads(json_str)
            except json.JSONDecodeError:
                print(f"[ollama_client] ERROR: Extracted JSON block but it's invalid.")
                print(f"[ollama_client] Extracted: {json_str[:300]}...")

    if parsed is None:
        # Last resort: try loading the whole cleaned text
        try:
            parsed = json.loads(clean_text)
        except json.JSONDecodeError:
            print("[ollama_client] ERROR: Could not parse JSON from LLM response.")
            print(f"[ollama_client] Raw text (first 500 chars): {raw_text[:500]}")
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

    # Fake analysis_data matching the actual structure main.py sends
    test_data = {
        "filename":       "suspicious_update.exe",
        "input_type":     "binary",
        "size_bytes":     204800,
        "sha256":         "a3f5c2d1e4b7890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "entropy":        7.8,
        "entropy_verdict":"CRITICAL — almost certainly packed malware",
        "dangerous_imports": [
            {"name": "CreateRemoteThread", "category": "Process Injection",    "score": 35},
            {"name": "WriteProcessMemory", "category": "Process Injection",    "score": 30},
            {"name": "VirtualAllocEx",     "category": "Process Injection",    "score": 30},
        ],
        "import_risk_score": 87,
        "compile_timestamp": "2089-01-01 00:00:00 UTC",
        "compile_timestamp_suspicious": True,
        "iocs": {
            "ips":     ["192.168.1.105", "45.33.32.156"],
            "domains": ["evil-update.ru", "malware-cdn.xyz"],
            "urls":    ["http://evil-update.ru/payload.bin"],
        },
        "vt_result": {
            "available":    True,
            "known":        True,
            "malicious":    3,
            "total":        70,
            "threat_names": ["Trojan.GenericKD", "Backdoor.Agent"],
            "message":      "Flagged as malicious by 3 engine(s)."
        },
        "correlation": {
            "matches_found":   True,
            "match_count":     2,
            "matched_iocs":    ["45.33.32.156"],
            "related_incidents": [
                {"incident_id": 1, "filename": "stage1.ps1", "timestamp": "2026-03-05", "shared_iocs": ["45.33.32.156"], "shared_count": 1}
            ],
            "campaign_flag":   False,
            "campaign_message": "Correlated with 1 previous incident sharing 1 IOC(s)."
        }
    }

    report = generate_report(test_data)
    print("\n===== FINAL REPORT =====")
    print(json.dumps(report, indent=2))

