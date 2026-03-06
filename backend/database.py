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
            findings_json TEXT
        )
    ''')
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
            iocs_json, vt_json, llm_json, correlation_json, findings_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        filename, timestamp, input_type, md5, sha1, sha256,
        size_bytes, entropy, risk_score, severity, threat_class,
        iocs_json, vt_json, llm_json, correlation_json, findings_json
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
    
    return [dict(row) for row in rows]

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
        "timestamp": row_dict.get("timestamp")
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

if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")
