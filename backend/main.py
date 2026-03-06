"""
ThreatSense — FastAPI Backend Orchestrator
==========================================
The hub of the ThreatSense platform.  Receives suspicious files,
routes them through the analysis pipeline, and returns structured
incident reports.

Endpoints
---------
POST /analyze               File upload → full pipeline → JSON report
GET  /incidents             History panel (summary list)
GET  /incidents/{id}        Full incident by ID
GET  /incidents/{id}/pdf    PDF export (bytes download)
GET  /stats                 Dashboard statistics
GET  /                      Health-check

Run
---
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import io
import json
import time
import logging
import traceback
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, Response
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
#  Environment
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
#  Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("threatsense")


# ---------------------------------------------------------------------------
#  Graceful imports — every optional module has a flag
# ---------------------------------------------------------------------------
# Database (required)
from database import init_db, save_incident, get_all_incidents, get_incident_by_id
from database import update_source_reputation, bump_source_total, get_source_reputation, get_all_blacklisted_sources

# Analyzers (required)
from analyzer import analyze_binary
from script_analyzer import analyze_script

# VirusTotal (required)
from virustotal import check_hash

# Correlation engine (required)
from correlation import run_correlation

# Email analyzer (bonus — graceful if missing)
try:
    from email_analyzer import analyze_email
    EMAIL_ANALYZER_AVAILABLE = True
    log.info("✓ email_analyzer loaded")
except ImportError:
    EMAIL_ANALYZER_AVAILABLE = False
    log.warning("✗ email_analyzer not available — .eml files will be treated as text")

# URL analyzer (bonus — graceful if missing)
try:
    from url_analyzer import analyze_url
    URL_ANALYZER_AVAILABLE = True
    log.info("✓ url_analyzer loaded")
except ImportError:
    URL_ANALYZER_AVAILABLE = False
    log.warning("✗ url_analyzer not available")

# Ollama LLM client (graceful — raw findings returned if unavailable)
try:
    from ollama_client import generate_report as llm_generate_report
    LLM_AVAILABLE = True
    log.info("✓ ollama_client loaded")
except ImportError:
    LLM_AVAILABLE = False
    log.warning("✗ ollama_client not available — LLM synthesis disabled")

# PDF generator (graceful — 503 returned if unavailable)
try:
    from pdf_generator import generate_pdf_report
    PDF_AVAILABLE = True
    log.info("✓ pdf_generator loaded")
except ImportError:
    PDF_AVAILABLE = False
    log.warning("✗ pdf_generator not available — PDF export disabled")


# ---------------------------------------------------------------------------
#  File type routing constants
# ---------------------------------------------------------------------------
SCRIPT_EXTENSIONS = {
    ".py", ".js", ".ps1", ".bat", ".sh", ".bash", ".cmd",
    ".vbs", ".rb", ".pl", ".php", ".lua", ".ts",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bin", ".dat", ".so", ".dylib",
    ".elf", ".o", ".scr", ".com", ".drv", ".ocx", ".cpl",
}

EMAIL_EXTENSIONS = {".eml", ".msg"}

# Magic bytes that identify binary formats regardless of extension
BINARY_MAGIC = {
    b"MZ":                       "pe",
    b"\x7fELF":                  "elf",
    b"\xfe\xed\xfa\xce":        "macho",
    b"\xfe\xed\xfa\xcf":        "macho",
    b"\xca\xfe\xba\xbe":        "macho_universal",
}


# ---------------------------------------------------------------------------
#  FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ThreatSense API",
    description="Automated Tier-1 SOC Analyst — drop a suspicious file, get an incident report.",
    version="1.0.0",
)

# CORS — allow React frontend on localhost:3000 and any origin for demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # wide-open for hackathon; tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
#  Startup event — initialise the database
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup():
    init_db()
    log.info("Database initialised")
    log.info("ThreatSense backend ready on port 8000")


# ═══════════════════════════════════════════════════════════════════════════
#  Helper: determine how to route the file
# ═══════════════════════════════════════════════════════════════════════════
def _route_file(file_bytes: bytes, filename: str) -> str:
    """
    Decide the analysis route: 'binary', 'script', or 'email'.
    Priority: magic bytes > extension > fallback to binary.
    """
    # 1. Check magic bytes first — never trust the extension alone
    for magic, _ in BINARY_MAGIC.items():
        if file_bytes[:len(magic)] == magic:
            return "binary"

    # 2. Check extension
    ext = ""
    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[1].lower()

    if ext in EMAIL_EXTENSIONS and EMAIL_ANALYZER_AVAILABLE:
        return "email"

    if ext in SCRIPT_EXTENSIONS:
        return "script"

    if ext in BINARY_EXTENSIONS:
        return "binary"

    # 3. Heuristic: if the file is predominantly printable ASCII, treat as script
    if file_bytes:
        sample = file_bytes[:4096]
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        ratio = printable / max(len(sample), 1)
        if ratio > 0.85:
            return "script"

    # 4. Default to binary
    return "binary"


# ═══════════════════════════════════════════════════════════════════════════
#  Helper: build the unified response dict from analyzer output
# ═══════════════════════════════════════════════════════════════════════════
def _build_response(
    findings: dict,
    filename: str,
    vt_result: dict,
    correlation: dict,
    llm_report: dict,
    incident_id: int,
) -> dict:
    """
    Assemble the final JSON matching the ThreatSense pipeline contract
    that Member 3's React frontend expects.
    """
    # Determine file_type from findings — analyzers return it under different keys
    file_type = findings.get("file_type", "Unknown")

    # Entropy
    entropy = findings.get("entropy", 0.0)
    entropy_verdict = findings.get("entropy_verdict", "")

    # Hashes — analyzers store them flat; frontend expects nested
    hashes = {
        "md5":    findings.get("md5", ""),
        "sha1":   findings.get("sha1", ""),
        "sha256": findings.get("sha256", ""),
    }

    # IOCs — normalise to the full 5-key dict
    iocs_raw = findings.get("iocs", {})
    iocs = {
        "ips":           iocs_raw.get("ips", []),
        "domains":       iocs_raw.get("domains", []),
        "urls":          iocs_raw.get("urls", []),
        "registry_keys": iocs_raw.get("registry_keys", []),
        "file_paths":    iocs_raw.get("file_paths", []),
    }

    return {
        "incident_id":      incident_id,
        "filename":         filename,
        "file_type":        file_type,
        "input_type":       findings.get("input_type", "binary"),

        "hashes":           hashes,

        "size_bytes":       findings.get("size_bytes", 0),
        "entropy":          entropy,
        "entropy_verdict":  entropy_verdict,

        "risk_score":       findings.get("risk_score", 0),

        "findings":         findings,   # raw analyzer output for the frontend

        "iocs":             iocs,

        "vt_result":        vt_result,
        "llm_report":       llm_report,
        "correlation":      correlation,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  POST /analyze — the core pipeline
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    source_domain: str = Form(""),
    source_ip: str = Form(""),
):
    """
    Full analysis pipeline:
      1. Read file bytes
      2. Detect type & route to analyzer
      3. VirusTotal hash lookup (hash only, never the file)
      4. Correlation engine (IOC cross-matching)
      5. LLM synthesis (local Ollama)
      6. Save to database
      7. Return structured JSON
    """
    start = time.time()
    filename = file.filename or "unknown"

    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {e}")

    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    log.info(f"━━━ Analysis started: {filename} ({len(file_bytes):,} bytes) ━━━")

    # ── Step 1: Route to the correct analyzer ─────────────────────────────
    route = _route_file(file_bytes, filename)
    log.info(f"  Route: {route}")

    try:
        if route == "email":
            findings = analyze_email(file_bytes, filename)
        elif route == "script":
            findings = analyze_script(file_bytes, filename)
        else:
            findings = analyze_binary(file_bytes, filename)
    except Exception as e:
        log.error(f"  Analyzer error: {e}")
        log.error(traceback.format_exc())
        # Return a minimal findings dict so the pipeline continues
        import hashlib
        findings = {
            "filename": filename,
            "input_type": route,
            "file_type": "Unknown (analyzer error)",
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "size_bytes": len(file_bytes),
            "entropy": 0.0,
            "entropy_verdict": "Analysis error",
            "risk_score": 0,
            "iocs": {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []},
            "error": str(e),
        }

    sha256 = findings.get("sha256", "")
    log.info(f"  SHA256: {sha256[:16]}…")
    log.info(f"  Risk score: {findings.get('risk_score', 0)}")

    # ── Step 2: VirusTotal lookup (hash only) ─────────────────────────────
    vt_result = {"available": False, "known": False, "malicious": 0, "total": 0,
                 "threat_names": [], "message": "VirusTotal lookup skipped"}
    try:
        if sha256:
            log.info("  VirusTotal: looking up hash…")
            vt_result = check_hash(sha256)
            log.info(f"  VirusTotal: {vt_result.get('message', 'done')}")
    except Exception as e:
        log.warning(f"  VirusTotal error (non-fatal): {e}")
        vt_result = {"available": False, "known": False, "malicious": 0, "total": 0,
                     "threat_names": [], "message": f"Error: {e}"}

    # ── Step 3: Correlation engine ────────────────────────────────────────
    correlation = {
        "matches_found": False, "match_count": 0, "matched_iocs": [],
        "related_incidents": [], "campaign_flag": False,
        "campaign_message": "No correlation data",
    }
    try:
        iocs = findings.get("iocs", {})
        if sha256 and iocs:
            log.info("  Correlation: scanning past incidents…")
            correlation = run_correlation(iocs, sha256)
            if correlation.get("matches_found"):
                log.info(f"  Correlation: ⚠ {correlation['match_count']} shared IOC(s) found!")
            else:
                log.info("  Correlation: no matches")
    except Exception as e:
        log.warning(f"  Correlation error (non-fatal): {e}")

    # ── Step 4: LLM synthesis (Ollama) ────────────────────────────────────
    llm_report = {
        "threat_classification": "Analysis Unavailable",
        "severity": "UNKNOWN",
        "confidence": 0,
        "attack_techniques": [],
        "behavioral_summary": "LLM synthesis unavailable. Review raw findings manually.",
        "executive_summary": "Automated analysis could not be completed. Manual review required.",
        "ioc_highlights": [],
        "remediation": ["Review raw findings in the technical section",
                        "Consult a security professional"],
        "analyst_notes": "LLM module not available",
    }

    if LLM_AVAILABLE:
        try:
            log.info("  LLM: generating report via Ollama…")
            # Build the data dict that ollama_client expects
            llm_input = {
                **findings,
                "vt_result": vt_result,
                "correlation": correlation,
            }
            llm_report = llm_generate_report(llm_input)
            log.info(f"  LLM: severity={llm_report.get('severity')} "
                     f"confidence={llm_report.get('confidence')}%")
        except Exception as e:
            log.warning(f"  LLM error (non-fatal): {e}")
            llm_report["analyst_notes"] = f"LLM error: {e}"
    else:
        log.info("  LLM: skipped (module not loaded)")

    # ── Step 5: Save to database ──────────────────────────────────────────
    incident_id = -1
    try:
        save_data = {
            "filename": filename,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "input_type": findings.get("input_type", route),
            "md5": findings.get("md5", ""),
            "sha1": findings.get("sha1", ""),
            "sha256": sha256,
            "size_bytes": findings.get("size_bytes", len(file_bytes)),
            "entropy": findings.get("entropy", 0.0),
            "risk_score": findings.get("risk_score", 0),
            "severity": llm_report.get("severity", "UNKNOWN"),
            "threat_class": llm_report.get("threat_classification", "Unknown"),
            "iocs": findings.get("iocs", {}),
            "vt_result": vt_result,
            "llm_report": llm_report,
            "correlation": correlation,
            "findings": findings,
            "file_type": findings.get("file_type", "Unknown"),
            "entropy_verdict": findings.get("entropy_verdict", ""),
            "source_domain": source_domain,
            "source_ip": source_ip,
        }
        incident_id = save_incident(save_data)
        log.info(f"  Database: saved as incident #{incident_id}")

        # ── Step 5.5: Update source reputation ────────────────────────
        sev = llm_report.get("severity", "UNKNOWN")
        if source_domain:
            try:
                update_source_reputation(source_domain, "domain", sev, incident_id)
                log.info(f"  Reputation: updated {source_domain} ({sev})")
            except Exception as e:
                log.warning(f"  Reputation update error: {e}")
        if source_ip and source_ip != source_domain:
            try:
                update_source_reputation(source_ip, "ip", sev, incident_id)
            except Exception:
                pass
    except Exception as e:
        log.error(f"  Database save error: {e}")
        log.error(traceback.format_exc())

    # ── Step 6: Build unified response ────────────────────────────────────
    elapsed = round(time.time() - start, 2)
    log.info(f"━━━ Analysis complete: {filename} → incident #{incident_id} in {elapsed}s ━━━")

    # ── Step 6: Look up source reputation for response ─────────────────
    source_rep = None
    if source_domain:
        try:
            source_rep = get_source_reputation(source_domain)
        except Exception:
            pass

    response = _build_response(findings, filename, vt_result, correlation,
                                llm_report, incident_id)
    response["analysis_time_seconds"] = elapsed
    if source_domain:
        response["source"] = {"domain": source_domain, "ip": source_ip}
    if source_rep:
        response["source_reputation"] = source_rep

    return JSONResponse(content=response)


# ═══════════════════════════════════════════════════════════════════════════
#  GET /reputation/{source} — source reputation lookup
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/reputation/{source}")
async def get_reputation(source: str):
    """Return the reputation data for a source domain or IP."""
    try:
        rep = get_source_reputation(source)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    if rep is None:
        return JSONResponse(content={"source": source, "score": 0, "label": "CLEAN", "total_files": 0, "malicious_files": 0})

    return JSONResponse(content=rep)


# ═══════════════════════════════════════════════════════════════════════════
#  POST /analyze-url — URL analysis endpoint (bonus)
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze-url")
async def analyze_url_endpoint(url: str = Query(..., description="URL to analyze")):
    """
    Analyze a URL string for malicious indicators.
    Bonus endpoint — not in the original spec but extends the platform.
    """
    if not URL_ANALYZER_AVAILABLE:
        raise HTTPException(status_code=503, detail="URL analyzer module not available")

    try:
        findings = analyze_url(url)
        return JSONResponse(content=findings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════
#  GET /incidents — history panel
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/incidents")
async def list_incidents():
    """Return all past incidents (summary fields only), newest first."""
    try:
        incidents = get_all_incidents()
        return JSONResponse(content=incidents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch incidents: {e}")


# ═══════════════════════════════════════════════════════════════════════════
#  GET /incidents/{id} — single full report
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: int):
    """Return full incident data with all JSON fields parsed."""
    try:
        incident = get_incident_by_id(incident_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found")

    # Enrich with live source reputation (score may have grown since original scan)
    src_domain = incident.get("source_domain", "")
    src_ip = incident.get("source_ip", "")
    if src_domain:
        incident["source"] = {"domain": src_domain, "ip": src_ip}
        try:
            rep = get_source_reputation(src_domain)
            if rep:
                incident["source_reputation"] = rep
        except Exception:
            pass

    return JSONResponse(content=incident)


# ═══════════════════════════════════════════════════════════════════════════
#  GET /incidents/{id}/pdf — PDF export
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/incidents/{incident_id}/pdf")
async def export_pdf(incident_id: int):
    """
    Generate and stream a professional PDF incident report.
    Calls Member 4's generate_pdf_report().
    """
    if not PDF_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="PDF generator module not available. Install reportlab and add pdf_generator.py.",
        )

    # Fetch incident data
    try:
        incident = get_incident_by_id(incident_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found")

    # Enrich with live source reputation for the PDF
    src_domain = incident.get("source_domain", "")
    src_ip = incident.get("source_ip", "")
    if src_domain:
        incident["source"] = {"domain": src_domain, "ip": src_ip}
        try:
            rep = get_source_reputation(src_domain)
            if rep:
                incident["source_reputation"] = rep
        except Exception:
            pass

    # Generate PDF bytes
    try:
        pdf_bytes = generate_pdf_report(incident)
    except Exception as e:
        log.error(f"PDF generation error: {e}")
        log.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    # Stream as downloadable file
    safe_filename = (incident.get("filename") or "incident").replace(" ", "_")
    download_name = f"ThreatSense_Report_{incident_id}_{safe_filename}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
#  GET /stats — dashboard statistics
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/stats")
async def get_stats():
    """
    Return aggregated stats for the dashboard:
    total incidents and breakdown by severity.
    """
    try:
        incidents = get_all_incidents()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    by_severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "BENIGN": 0,
        "UNKNOWN": 0,
    }

    for inc in incidents:
        sev = (inc.get("severity") or "UNKNOWN").upper()
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity["UNKNOWN"] += 1

    return JSONResponse(content={
        "total": len(incidents),
        "by_severity": by_severity,
        "blacklisted_sources": len(get_all_blacklisted_sources(31)),
    })


# ═══════════════════════════════════════════════════════════════════════════
#  GET / — health check
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/")
async def health_check():
    """Simple health check — judges/Member 3 can hit this to verify the backend is running."""
    return {
        "status": "running",
        "platform": "ThreatSense",
        "version": "1.0.0",
        "modules": {
            "analyzer": True,
            "script_analyzer": True,
            "email_analyzer": EMAIL_ANALYZER_AVAILABLE,
            "url_analyzer": URL_ANALYZER_AVAILABLE,
            "virustotal": True,
            "correlation": True,
            "ollama_llm": LLM_AVAILABLE,
            "pdf_generator": PDF_AVAILABLE,
        },
    }


# ---------------------------------------------------------------------------
#  Run with: python main.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    log.info("Starting ThreatSense backend on 0.0.0.0:8000")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
