import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve VirusTotal API key
VT_API_KEY = os.getenv("VT_API_KEY")

def check_hash(sha256: str) -> dict:
    """
    Takes a SHA256 hash string. Makes one GET request to VirusTotal. 
    Returns how many engines flagged it and what names they used.
    
    The privacy guarantee: Never send the file. Only the hash.
    """
    
    # Base fallback structure
    result = {
        "available": False,
        "known": False,
        "malicious": 0,
        "total": 0,
        "threat_names": [],
        "message": ""
    }
    
    if not VT_API_KEY:
        result["reason"] = "VT_API_KEY environment variable not set."
        return result
        
    if not sha256 or not isinstance(sha256, str):
        result["reason"] = "Invalid SHA256 hash provided."
        return result

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # 404: Hash not found in VirusTotal
        if response.status_code == 404:
            result["available"] = True
            result["known"] = False
            result["message"] = "Not seen before — possible novel sample"
            return result
            
        # 429: Rate limited
        if response.status_code == 429:
            result["available"] = False
            result["reason"] = "Rate limited"
            return result
            
        # 200: Successfully retrieved analysis
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            timeout = stats.get("timeout", 0)
            type_unsupported = stats.get("type-unsupported", 0)
            
            # Sum all stat values for total
            total = malicious + undetected + suspicious + harmless + timeout + type_unsupported
            
            # Deduplicate threat names
            threat_names = set()
            for engine, scan in results.items():
                if scan.get("category") == "malicious":
                    name = scan.get("result")
                    if name:
                        threat_names.add(name)
                        
            # Format successful structure
            result["available"] = True
            result["known"] = True
            result["malicious"] = malicious
            result["total"] = total
            result["threat_names"] = list(threat_names)
            
            if malicious == 0:
                result["message"] = "No engines detected a threat."
            else:
                result["message"] = f"Flagged as malicious by {malicious} engine(s)."
                
            return result
            
        # Any other status code -> Fail gracefully
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        result["available"] = False
        result["reason"] = f"Request exception: {str(e)}"
        return result
        
    except Exception as e:
        result["available"] = False
        result["reason"] = f"Unknown exception: {str(e)}"
        return result

if __name__ == "__main__":
    # Test block using the EICAR test file hash mentioned in the project bible
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print(f"Testing VirusTotal API with EICAR hash: {eicar_hash}")
    
    if not VT_API_KEY:
        print("Note: VT_API_KEY is not set. Output should gracefully indicate failure.")
        
    result = check_hash(eicar_hash)
    
    import json
    print(json.dumps(result, indent=2))
