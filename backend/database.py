import sqlite3
import json
import os
from datetime import datetime

# Define DB path in the same directory as this file
DB_PATH = os.path.join(os.path.dirname(__file__), "threatsense.db")

def _get_connection():
    """Returns a connection to the SQLite database."""
    return sqlite3.connect(DB_PATH)

def init_db():
    """Creates table if not exists, call on startup"""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            timestamp TEXT,
            input_type TEXT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            size_bytes INTEGER,
            entropy REAL,
            risk_score INTEGER,
            severity TEXT,
            threat_class TEXT,
            iocs_json TEXT,
            vt_json TEXT,
            llm_json TEXT,
            correlation_json TEXT,
            findings_json TEXT,
            source_domain TEXT,
            source_ip TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS source_reputation (
            source      TEXT PRIMARY KEY,
            source_type TEXT,
            score       INTEGER DEFAULT 0,
            total_files INTEGER DEFAULT 0,
            malicious_files INTEGER DEFAULT 0,
            first_seen  TEXT,
            last_seen   TEXT,
            incidents   TEXT DEFAULT '[]'
        )
    ''')

    # ── Schema migrations for existing databases ──
    # ALTER TABLE is safe to retry — silently ignore if column already exists
    for col, col_type in [("source_domain", "TEXT"), ("source_ip", "TEXT")]:
        try:
            cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.commit()
    conn.close()

def save_incident(data: dict) -> int:
    """Inserts row, returns new ID"""
    conn = _get_connection()
    cursor = conn.cursor()
    
    # Extract root fields
    filename = data.get("filename", "")
    timestamp = data.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    input_type = data.get("input_type", "")
    
    # Hashes encapsulation
    hashes = data.get("hashes", {})
    md5 = hashes.get("md5", "") or data.get("md5", "")
    sha1 = hashes.get("sha1", "") or data.get("sha1", "")
    sha256 = hashes.get("sha256", "") or data.get("sha256", "")
    
    size_bytes = data.get("size_bytes", 0)
    entropy = data.get("entropy", 0.0)
    risk_score = data.get("risk_score", 0)
    
    # LLM properties that need to be captured as columns
    llm_report = data.get("llm_report", {})
    severity = llm_report.get("severity", "UNKNOWN") if "severity" not in data else data.get("severity")
    threat_class = llm_report.get("threat_classification", "Analysis Unavailable") if "threat_class" not in data else data.get("threat_class")
    
    # Find extra root keys not formally in DB schema (like file_type or entropy_verdict)
    findings = data.get("findings", {}).copy()
    if "file_type" in data:
        findings["_mapped_file_type"] = data["file_type"]
    if "entropy_verdict" in data:
        findings["_mapped_entropy_verdict"] = data["entropy_verdict"]
    
    # Source info (from file_monitor Chrome integration)
    source_domain = data.get("source_domain", "")
    source_ip = data.get("source_ip", "")

    # Complex fields to JSON
    iocs_json = json.dumps(data.get("iocs", {}))
    vt_json = json.dumps(data.get("vt_result", {}))
    llm_json = json.dumps(llm_report)
    correlation_json = json.dumps(data.get("correlation", {}))
    findings_json = json.dumps(findings)

    cursor.execute('''
        INSERT INTO incidents (
            filename, timestamp, input_type, md5, sha1, sha256,
            size_bytes, entropy, risk_score, severity, threat_class,
            iocs_json, vt_json, llm_json, correlation_json, findings_json,
            source_domain, source_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        filename, timestamp, input_type, md5, sha1, sha256,
        size_bytes, entropy, risk_score, severity, threat_class,
        iocs_json, vt_json, llm_json, correlation_json, findings_json,
        source_domain, source_ip
    ))
    
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return incident_id

def get_all_incidents() -> list:
    """Returns all rows newest first, summary fields only"""
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, timestamp, severity, threat_class
        FROM incidents
        ORDER BY timestamp DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        d = dict(row)
        d["incident_id"] = d.pop("id")  # match frontend contract
        results.append(d)
    return results

def get_incident_by_id(incident_id: int) -> dict:
    """Returns full row with all JSON parsed"""
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
        
    row_dict = dict(row)
    
    # Reconstruct the expected complex structured result dictionary
    incident = {
        "incident_id": row_dict.get("id"),
        "filename": row_dict.get("filename"),
        "input_type": row_dict.get("input_type"),
        "hashes": {
            "md5": row_dict.get("md5"),
            "sha1": row_dict.get("sha1"),
            "sha256": row_dict.get("sha256")
        },
        "size_bytes": row_dict.get("size_bytes"),
        "entropy": row_dict.get("entropy"),
        "risk_score": row_dict.get("risk_score"),
        "severity": row_dict.get("severity", "UNKNOWN"),
        "threat_class": row_dict.get("threat_class", ""),
        "timestamp": row_dict.get("timestamp"),
        "source_domain": row_dict.get("source_domain", ""),
        "source_ip": row_dict.get("source_ip", ""),
    }
    
    # Reconstruct JSON objects
    incident["iocs"] = json.loads(row_dict.get("iocs_json") or "{}")
    incident["vt_result"] = json.loads(row_dict.get("vt_json") or "{}")
    incident["llm_report"] = json.loads(row_dict.get("llm_json") or "{}")
    incident["correlation"] = json.loads(row_dict.get("correlation_json") or "{}")
    incident["findings"] = json.loads(row_dict.get("findings_json") or "{}")
    
    # Reconstruct the extra root properties if provided in findings
    if "_mapped_file_type" in incident["findings"]:
        incident["file_type"] = incident["findings"].pop("_mapped_file_type")
    
    if "_mapped_entropy_verdict" in incident["findings"]:
        incident["entropy_verdict"] = incident["findings"].pop("_mapped_entropy_verdict")
        
    return incident

def get_all_iocs_except(sha256: str) -> list:
    """Used by correlation, returns all past IOCs"""
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, timestamp, iocs_json
        FROM incidents
        WHERE sha256 != ? OR sha256 IS NULL
    ''', (sha256,))
    
    rows = cursor.fetchall()
    conn.close()
    
    past_iocs = []
    for row in rows:
        data = {
            "incident_id": row["id"],
            "filename": row["filename"],
            "timestamp": row["timestamp"],
            "iocs": json.loads(row["iocs_json"] or "{}")
        }
        past_iocs.append(data)
        
    return past_iocs

def get_incidents_by_sha256(sha256: str) -> list:
    """Returns all incidents with the same SHA256, ordered by timestamp.
    Used by propagation chain detection to find the same malware across sources."""
    if not sha256:
        return []
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, filename, timestamp, sha256,
               source_domain, source_ip, severity
        FROM incidents
        WHERE sha256 = ?
        ORDER BY timestamp ASC
    ''', (sha256,))

    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "incident_id": row["id"],
            "filename": row["filename"],
            "timestamp": row["timestamp"],
            "source_domain": row["source_domain"] or "",
            "source_ip": row["source_ip"] or "",
            "severity": row["severity"] or "UNKNOWN",
        })
    return results

# ─── Source reputation helpers ────────────────────────────────────────────────

SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20}


def update_source_reputation(source: str, source_type: str, severity: str, incident_id: int):
    """Upsert the reputation score for a source domain/IP."""
    points = SEVERITY_POINTS.get(severity, 0)
    if points == 0:
        return  # only track MEDIUM+ severity

    now = datetime.utcnow().isoformat() + "Z"
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT score, total_files, malicious_files, incidents FROM source_reputation WHERE source = ?", (source,))
    row = cursor.fetchone()

    if row:
        old_score, total, mal, inc_json = row
        inc_list = json.loads(inc_json or "[]")
        if incident_id not in inc_list:
            inc_list.append(incident_id)
        new_score = min(old_score + points, 100)
        cursor.execute('''
            UPDATE source_reputation
            SET score = ?, total_files = ?, malicious_files = ?, last_seen = ?, incidents = ?
            WHERE source = ?
        ''', (new_score, total + 1, mal + 1, now, json.dumps(inc_list), source))
    else:
        cursor.execute('''
            INSERT INTO source_reputation (source, source_type, score, total_files, malicious_files, first_seen, last_seen, incidents)
            VALUES (?, ?, ?, 1, 1, ?, ?, ?)
        ''', (source, source_type, points, now, now, json.dumps([incident_id])))

    conn.commit()
    conn.close()


def bump_source_total(source: str, source_type: str):
    """Record that a file was downloaded from this source (even if benign)."""
    now = datetime.utcnow().isoformat() + "Z"
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT total_files FROM source_reputation WHERE source = ?", (source,))
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE source_reputation SET total_files = ?, last_seen = ? WHERE source = ?",
                       (row[0] + 1, now, source))
    else:
        cursor.execute('''
            INSERT INTO source_reputation (source, source_type, score, total_files, malicious_files, first_seen, last_seen, incidents)
            VALUES (?, ?, 0, 1, 0, ?, ?, '[]')
        ''', (source, source_type, now, now))

    conn.commit()
    conn.close()


def get_source_reputation(source: str) -> dict | None:
    """Look up reputation for a domain or IP. Returns None if unknown."""
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM source_reputation WHERE source = ?", (source,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["incidents"] = json.loads(d.get("incidents") or "[]")
    # Add label
    s = d["score"]
    if s >= 61:
        d["label"] = "BLACKLISTED"
    elif s >= 31:
        d["label"] = "MALICIOUS"
    elif s >= 1:
        d["label"] = "SUSPICIOUS"
    else:
        d["label"] = "CLEAN"
    return d


def get_all_blacklisted_sources(min_score: int = 1) -> list:
    """Return all sources with reputation score >= min_score."""
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM source_reputation WHERE score >= ? ORDER BY score DESC", (min_score,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        d = dict(row)
        d["incidents"] = json.loads(d.get("incidents") or "[]")
        s = d["score"]
        d["label"] = "BLACKLISTED" if s >= 61 else "MALICIOUS" if s >= 31 else "SUSPICIOUS" if s >= 1 else "CLEAN"
        results.append(d)
    return results


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")
