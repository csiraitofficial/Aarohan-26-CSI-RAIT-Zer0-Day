import json
import re
from database import get_all_iocs_except, get_incidents_by_sha256


def detect_propagation_chain(sha256: str, current_source_domain: str,
                              current_source_ip: str, current_incident_id: int) -> dict:
    """
    Detect if the same malware (by SHA256) has been seen from different sources.
    Builds a chronological propagation chain showing how the file spread.

    Returns:
        dict with chain_detected, chain_length, chain, chain_message, etc.
    """
    result = {
        "chain_detected": False,
        "chain_length": 0,
        "chain": [],
        "chain_message": "No propagation chain detected.",
    }

    if not sha256:
        return result

    current_source = current_source_domain or current_source_ip or ""
    if not current_source:
        return result

    try:
        past = get_incidents_by_sha256(sha256)
    except Exception:
        return result

    # Build unique source nodes from past incidents (chronological order)
    seen_sources = {}  # source -> first occurrence dict
    for inc in past:
        src = inc.get("source_domain") or inc.get("source_ip") or ""
        if not src:
            continue
        # Skip if same source as current (not a hop)
        # Keep the first occurrence per source for the chain
        if src not in seen_sources:
            seen_sources[src] = {
                "source": src,
                "source_ip": inc.get("source_ip", ""),
                "incident_id": inc.get("incident_id"),
                "filename": inc.get("filename", ""),
                "timestamp": inc.get("timestamp", ""),
                "severity": inc.get("severity", "UNKNOWN"),
            }

    # Add current source to chain if not already present
    if current_source not in seen_sources:
        seen_sources[current_source] = {
            "source": current_source,
            "source_ip": current_source_ip or "",
            "incident_id": current_incident_id,
            "filename": "",
            "timestamp": "",
            "severity": "",
        }

    # A chain requires at least 2 distinct sources
    if len(seen_sources) < 2:
        return result

    # Build chronological chain (ordered by first appearance)
    chain = list(seen_sources.values())

    # Build human-readable chain string: Source1 → Source2 → Source3
    chain_str = " → ".join(
        f"{node['source']} (#{node['incident_id']})"
        for node in chain
    )

    result["chain_detected"] = True
    result["chain_length"] = len(chain)
    result["chain"] = chain
    result["chain_message"] = (
        f"PROPAGATION CHAIN: This malware has been observed spreading across "
        f"{len(chain)} distinct sources: {chain_str}. "
        f"This indicates active malware propagation between hosts. "
        f"All sources in this chain should be investigated and isolated."
    )

    return result


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range (should not trigger correlation)."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        # 169.254.0.0/16 (link-local)
        if octets[0] == 169 and octets[1] == 254:
            return True
    except (ValueError, IndexError):
        pass
    return False


# Simple regex to identify IP-shaped strings for filtering
_RE_IP = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
)


def flatten_iocs(iocs_dict: dict) -> set:
    """
    Flattens an IOC dictionary into a single set of unique string values.
    Filters out private/reserved IPs to avoid false correlation matches.
    Expects format: {"ips": [...], "domains": [...], "urls": [...], "registry_keys": [...], "file_paths": [...]}
    """
    flattened = set()
    if not isinstance(iocs_dict, dict):
        return flattened
        
    for category, values in iocs_dict.items():
        if isinstance(values, list):
            for val in values:
                if isinstance(val, str) and val.strip():
                    clean = val.strip()
                    # Skip private IPs — they cause false correlations
                    if _RE_IP.match(clean) and _is_private_ip(clean):
                        continue
                    flattened.add(clean)
                    
    return flattened

def run_correlation(current_iocs: dict, current_sha256: str) -> dict:
    """
    Takes the IOCs from the current analysis and its SHA256 hash.
    Queries all past incidents from the database.
    Finds any that share IOCs. Returns a correlation report.
    """
    result = {
        "matches_found": False,
        "match_count": 0,
        "matched_iocs": [],
        "related_incidents": [],
        "campaign_flag": False,
        "campaign_message": "No correlation with past incidents."
    }
    
    # Early exit if no current IOCs or no SHA256 provided
    if not current_iocs or not current_sha256:
        return result
        
    current_set = flatten_iocs(current_iocs)
    if not current_set:
        return result
        
    try:
        # Fetch all past incidents excluding the current file's hash
        past_incidents = get_all_iocs_except(current_sha256)
    except Exception as e:
        result["campaign_message"] = f"Error querying past incidents: {str(e)}"
        return result
        
    all_matched_iocs = set()
    
    for past in past_incidents:
        past_iocs_dict = past.get("iocs", {})
        past_set = flatten_iocs(past_iocs_dict)
        
        shared = current_set & past_set
        
        if shared:
            all_matched_iocs.update(shared)
            
            related_incident = {
                "incident_id": past.get("incident_id"),
                "filename": past.get("filename"),
                "timestamp": past.get("timestamp"),
                "shared_iocs": list(shared),
                "shared_count": len(shared)
            }
            result["related_incidents"].append(related_incident)
            
    # Update final structure based on results
    if result["related_incidents"]:
        result["matches_found"] = True
        result["match_count"] = len(all_matched_iocs)
        result["matched_iocs"] = list(all_matched_iocs)
        
        related_count = len(result["related_incidents"])
        
        if related_count >= 2:
            result["campaign_flag"] = True
            result["campaign_message"] = f"CAMPAIGN DETECTED: Correlated with {related_count} previous distinct incidents sharing identical command/control infrastructure or IOCs."
        else:
            result["campaign_message"] = f"Correlated with 1 previous incident sharing {result['match_count']} IOC(s)."
            
    return result

if __name__ == "__main__":
    # Standard test simulating correlation against the EICAR test or a shared IP
    test_iocs = {
        "ips": ["193.42.11.23"],
        "domains": ["evil-domain.ru"]
    }
    test_sha256 = "test_sha256_hash_123"
    
    print("Testing correlation engine...")
    try:
        corr_result = run_correlation(test_iocs, test_sha256)
        print(json.dumps(corr_result, indent=2))
        print("Test complete. Database access was successful if no exception above.")
    except Exception as e:
        print(f"Error testing correlation: {str(e)}\nCheck if database is properly initialized.")
