import json
from database import get_all_iocs_except

def flatten_iocs(iocs_dict: dict) -> set:
    """
    Flattens an IOC dictionary into a single set of unique string values.
    Expects format: {"ips": [...], "domains": [...], "urls": [...], "registry_keys": [...], "file_paths": [...]}
    """
    flattened = set()
    if not isinstance(iocs_dict, dict):
        return flattened
        
    for category, values in iocs_dict.items():
        if isinstance(values, list):
            for val in values:
                if isinstance(val, str) and val.strip():
                    flattened.add(val.strip())
                    
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
