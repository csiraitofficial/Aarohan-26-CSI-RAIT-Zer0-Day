import urllib.parse
import re
import hashlib
from datetime import datetime

# Common suspicious URL patterns
SUSPICIOUS_PATTERNS = {
    r"https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}": ("Hardcoded IP in URL", 30),
    r"\.exe$|\.dll$|\.bin$": ("Executable Payload Download", 40),
    r"\.ps1$|\.bat$|\.vbs$|\.sh$|\.py$": ("Script Payload Download", 35),
    r"base64[_-]*[0-9a-zA-Z+/=]{20,}": ("Base64 Obfuscation in URL", 45),
    r"(?i)(admin|login|bank|paypal|account|secure).{0,10}\.(tk|ml|ga|cf|gq|xyz|top|pw)": ("Suspicious TLD/Phishing Pattern", 30),
    r"(\%[0-9A-Fa-f]{2}){5,}": ("Heavy URL Encoding", 20),
    r"php\?.*(cmd|exec|eval)=": ("Command Injection Pattern", 45),
    r"\.\.\/\.\.\/": ("Path Traversal Pattern", 40)
}

def analyze_url(url: str) -> dict:
    """
    Analyzes a URL string for malicious indicators.
    Returns a findings dictionary conforming to the ThreatSense schema.
    """
    url = url.strip()
    
    # 1. Compute hashes of the URL string itself (useful for unique ID/storage)
    url_bytes = url.encode('utf-8')
    md5 = hashlib.md5(url_bytes).hexdigest()
    sha1 = hashlib.sha1(url_bytes).hexdigest()
    sha256 = hashlib.sha256(url_bytes).hexdigest()
    
    # 2. Parse URL components
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
    except Exception:
        domain, path, query, scheme = "", "", "", ""

    # 3. Extract IOCs
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [url],  # The URL itself is the primary IOC
        "registry_keys": [],
        "file_paths": []
    }
    
    # Check if domain is an IP address
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\:[0-9]{1,5})?$"
    if re.match(ip_pattern, domain):
        iocs["ips"].append(domain.split(':')[0])  # Strip port if present
    elif domain:
        iocs["domains"].append(domain)
        
    # 4. Pattern matching for risk score
    risk_score = 0
    suspicious_indicators = []
    
    # Check scheme
    if scheme == "http":
        suspicious_indicators.append({"indicator": "Unencrypted HTTP Scheme", "category": "Transport", "score": 10})
        risk_score += 10
    
    # Check against known suspicious regex patterns
    for pattern, (category_desc, score_val) in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, url, re.IGNORECASE):
            suspicious_indicators.append({
                "indicator": category_desc,
                "category": "Pattern Match",
                "score": score_val,
                "matched_pattern": pattern
            })
            risk_score += score_val
            
    # Check URL length (extremely long URLs can be buffer overflow attempts or carry payloads)
    if len(url) > 200:
        suspicious_indicators.append({
            "indicator": f"Unusually long URL ({len(url)} chars)",
            "category": "Anomaly",
            "score": 15
        })
        risk_score += 15
        
    if len(query) > 100:
        suspicious_indicators.append({
            "indicator": "Extremely large query string",
            "category": "Anomaly",
            "score": 15
        })
        risk_score += 15

    # Cap risk score at 100
    risk_score = min(score for score in [risk_score, 100])
    
    # 5. Determine pseudo-entropy (variance in character usage in the URL)
    # This isn't as critical as binary entropy, but high entropy in a URL path often indicates data exfiltration or packed parameters.
    char_counts = {}
    for char in url:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    import math
    entropy = 0.0
    if len(url) > 0:
        for count in char_counts.values():
            p_x = count / len(url)
            entropy += - p_x * math.log2(p_x)
            
    if entropy < 3.5:
        entropy_verdict = "Normal - typical URL text"
    elif entropy < 4.5:
        entropy_verdict = "Elevated - possible encoding or dense parameters"
    else:
        entropy_verdict = "High - likely encrypted parameters, base64 data, or exfiltration"
        # Add risk score for very high entropy urls
        if entropy >= 4.5:
             suspicious_indicators.append({
                "indicator": "High URL character entropy",
                "category": "Obfuscation/Exfiltration",
                "score": 20
            })
             risk_score = min(100, risk_score + 20)
    
    # Construct final dictionary matching expected schema
    return {
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
        "size_bytes": len(url_bytes),
        "entropy": entropy,
        "entropy_verdict": entropy_verdict,
        "url_components": {
            "scheme": scheme,
            "domain": domain,
            "path": path,
            "query": query
        },
        "suspicious_indicators": suspicious_indicators,
        "iocs": iocs,
        "risk_score": risk_score,
        "input_type": "url",
        "file_type": "URL String"
    }

if __name__ == "__main__":
    # Test cases
    test_urls = [
        "https://www.google.com/search?q=threatsense",
        "http://193.42.11.23/stage2.ps1",
        "https://secure-login-paypal.xyz/auth.php?cmd=exec&payload=base64_QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "http://evil-domain.ru/../../etc/passwd"
    ]
    
    for test_url in test_urls:
        print(f"\\n--- Analyzing: {test_url} ---")
        result = analyze_url(test_url)
        import json
        print(json.dumps(result, indent=2))
