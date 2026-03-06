"""
Comprehensive test suite for analyzer.py
==========================================
Tests all public and internal functions against expected behavior
from the ThreatSense project specification.
"""

import hashlib
import json
import math
import os
import struct
import sys
import unittest
from unittest.mock import patch, MagicMock
from collections import Counter

# Ensure backend directory is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import (
    analyze_binary,
    _compute_hashes,
    _calculate_entropy,
    _entropy_verdict,
    _extract_strings,
    _extract_ips,
    _extract_domains,
    _extract_urls,
    _extract_registry_keys,
    _extract_file_paths,
    _extract_iocs_from_strings,
    _detect_file_type,
    _analyze_pe,
    _select_interesting_strings,
    _calculate_risk_score,
    _generate_verdict,
    DANGEROUS_IMPORTS,
    MAGIC_BYTES,
    BENIGN_DOMAINS,
)


# ==========================================================================
#  Test: _compute_hashes
# ==========================================================================
class TestComputeHashes(unittest.TestCase):
    """Verify MD5, SHA1, SHA256 are correctly computed."""

    def test_known_hash(self):
        data = b"hello world"
        h = _compute_hashes(data)
        self.assertEqual(h["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(h["sha1"], hashlib.sha1(data).hexdigest())
        self.assertEqual(h["sha256"], hashlib.sha256(data).hexdigest())

    def test_empty_bytes(self):
        h = _compute_hashes(b"")
        # SHA256 of empty is well-known
        self.assertEqual(h["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_returns_all_three_keys(self):
        h = _compute_hashes(b"anything")
        self.assertIn("md5", h)
        self.assertIn("sha1", h)
        self.assertIn("sha256", h)

    def test_md5_length(self):
        h = _compute_hashes(b"test")
        self.assertEqual(len(h["md5"]), 32)

    def test_sha1_length(self):
        h = _compute_hashes(b"test")
        self.assertEqual(len(h["sha1"]), 40)

    def test_sha256_length(self):
        h = _compute_hashes(b"test")
        self.assertEqual(len(h["sha256"]), 64)

    def test_deterministic(self):
        data = b"deterministic test"
        self.assertEqual(_compute_hashes(data), _compute_hashes(data))


# ==========================================================================
#  Test: _calculate_entropy
# ==========================================================================
class TestCalculateEntropy(unittest.TestCase):
    """Verify Shannon entropy calculation."""

    def test_empty_bytes_returns_zero(self):
        self.assertEqual(_calculate_entropy(b""), 0.0)

    def test_single_byte_repeated(self):
        # All same byte -> 0 entropy
        self.assertAlmostEqual(_calculate_entropy(b"\x41" * 1000), 0.0, places=2)

    def test_two_byte_equal_distribution(self):
        # 50/50 distribution of two values -> entropy = 1.0
        data = b"\x00\x01" * 500
        self.assertAlmostEqual(_calculate_entropy(data), 1.0, places=2)

    def test_all_256_bytes_equal(self):
        # All 256 values equally distributed -> entropy = 8.0
        data = bytes(range(256)) * 100
        self.assertAlmostEqual(_calculate_entropy(data), 8.0, places=1)

    def test_plain_text_entropy(self):
        # Plain English text -> moderate entropy (2-5 range)
        data = b"The quick brown fox jumps over the lazy dog. " * 20
        entropy = _calculate_entropy(data)
        self.assertGreater(entropy, 2.0)
        self.assertLess(entropy, 5.5)

    def test_random_bytes_high_entropy(self):
        # Near-random bytes -> high entropy (close to 8.0)
        import random
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        entropy = _calculate_entropy(data)
        self.assertGreater(entropy, 7.5)

    def test_return_type_is_float(self):
        self.assertIsInstance(_calculate_entropy(b"test"), float)

    def test_entropy_max_8(self):
        """Entropy should never exceed 8.0 for byte data."""
        data = bytes(range(256)) * 100
        self.assertLessEqual(_calculate_entropy(data), 8.0)


# ==========================================================================
#  Test: _entropy_verdict
# ==========================================================================
class TestEntropyVerdict(unittest.TestCase):
    """Verify entropy-to-human-readable mapping matches spec thresholds."""

    def test_low_entropy(self):
        self.assertIn("Low", _entropy_verdict(2.0))
        self.assertIn("Low", _entropy_verdict(0.0))
        self.assertIn("Low", _entropy_verdict(3.49))

    def test_normal_entropy(self):
        self.assertIn("Normal", _entropy_verdict(3.5))
        self.assertIn("Normal", _entropy_verdict(5.0))
        self.assertIn("Normal", _entropy_verdict(5.99))

    def test_elevated_entropy(self):
        self.assertIn("Elevated", _entropy_verdict(6.0))
        self.assertIn("Elevated", _entropy_verdict(7.0))
        self.assertIn("Elevated", _entropy_verdict(7.19))

    def test_high_entropy(self):
        result = _entropy_verdict(7.2)
        self.assertIn("HIGH", result)
        result = _entropy_verdict(7.79)
        self.assertIn("HIGH", result)

    def test_critical_entropy(self):
        result = _entropy_verdict(7.8)
        self.assertIn("CRITICAL", result)
        result = _entropy_verdict(8.0)
        self.assertIn("CRITICAL", result)


# ==========================================================================
#  Test: _extract_strings
# ==========================================================================
class TestExtractStrings(unittest.TestCase):
    """Verify string extraction from binary data."""

    def test_basic_string_extraction(self):
        data = b"\x00\x00\x00Hello World\x00\x00\x00"
        strings = _extract_strings(data, min_length=5)
        self.assertIn("Hello World", strings)

    def test_min_length_filter(self):
        data = b"\x00Hi\x00LongerString\x00"
        strings = _extract_strings(data, min_length=5)
        self.assertNotIn("Hi", strings)
        self.assertIn("LongerString", strings)

    def test_embedded_ip(self):
        data = b"\x00\x00192.168.1.100\x00\x00"
        strings = _extract_strings(data, min_length=5)
        self.assertIn("192.168.1.100", strings)

    def test_empty_data(self):
        self.assertEqual(_extract_strings(b""), [])

    def test_no_printable_strings(self):
        data = bytes(range(0, 0x20)) * 10
        strings = _extract_strings(data, min_length=5)
        self.assertEqual(strings, [])

    def test_deduplication(self):
        data = b"\x00Hello World\x00\x00Hello World\x00"
        strings = _extract_strings(data, min_length=5)
        count = strings.count("Hello World")
        self.assertEqual(count, 1, "Strings should be deduplicated")

    def test_url_extraction(self):
        data = b"\x00http://evil.com/payload.exe\x00"
        strings = _extract_strings(data, min_length=5)
        self.assertIn("http://evil.com/payload.exe", strings)


# ==========================================================================
#  Test: IOC extraction functions
# ==========================================================================
class TestExtractIPs(unittest.TestCase):
    """Verify IP address extraction and filtering."""

    def test_valid_ip(self):
        ips = _extract_ips("Connection to 193.42.11.23 on port 443")
        self.assertIn("193.42.11.23", ips)

    def test_multiple_ips(self):
        text = "src: 10.0.0.1 dst: 192.168.1.1"
        ips = _extract_ips(text)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("192.168.1.1", ips)

    def test_filter_loopback(self):
        ips = _extract_ips("localhost 127.0.0.1")
        self.assertNotIn("127.0.0.1", ips)

    def test_filter_zero(self):
        ips = _extract_ips("addr 0.0.0.0")
        self.assertNotIn("0.0.0.0", ips)

    def test_filter_broadcast(self):
        ips = _extract_ips("broadcast 255.255.255.255")
        self.assertNotIn("255.255.255.255", ips)

    def test_no_ips(self):
        self.assertEqual(_extract_ips("no ips here"), [])

    def test_returns_sorted_list(self):
        ips = _extract_ips("10.0.0.2 10.0.0.1 10.0.0.3")
        self.assertEqual(ips, sorted(ips))


class TestExtractDomains(unittest.TestCase):
    """Verify domain extraction and benign filtering."""

    def test_malicious_domain(self):
        domains = _extract_domains("connected to evil.ru for C2")
        self.assertIn("evil.ru", domains)

    def test_filter_benign(self):
        domains = _extract_domains("using google.com and microsoft.com")
        self.assertNotIn("google.com", domains)
        self.assertNotIn("microsoft.com", domains)

    def test_multiple_domains(self):
        domains = _extract_domains("evil.xyz and bad.top and malware.cc")
        self.assertIn("evil.xyz", domains)
        self.assertIn("bad.top", domains)
        self.assertIn("malware.cc", domains)

    def test_no_domains(self):
        self.assertEqual(_extract_domains("no domains here"), [])


class TestExtractUrls(unittest.TestCase):
    """Verify URL extraction."""

    def test_http_url(self):
        urls = _extract_urls("download from http://evil.com/malware.exe")
        self.assertTrue(any("evil.com" in u for u in urls))

    def test_https_url(self):
        urls = _extract_urls("connect to https://c2.bad.org/stage2")
        self.assertTrue(any("c2.bad.org" in u for u in urls))

    def test_url_cleanup(self):
        # Should strip trailing punctuation
        urls = _extract_urls("see http://example.net/path.")
        for u in urls:
            self.assertFalse(u.endswith("."))

    def test_short_urls_filtered(self):
        # URLs shorter than 10 chars should be filtered
        urls = _extract_urls("http://x")
        self.assertEqual(urls, [])


class TestExtractRegistryKeys(unittest.TestCase):
    """Verify Windows registry key extraction."""

    def test_run_key(self):
        text = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
        keys = _extract_registry_keys(text)
        self.assertTrue(len(keys) > 0)
        self.assertTrue(any("CurrentVersion" in k for k in keys))

    def test_no_registry_keys(self):
        self.assertEqual(_extract_registry_keys("no registry here"), [])


class TestExtractFilePaths(unittest.TestCase):
    """Verify Windows file path extraction."""

    def test_system32_path(self):
        text = r"C:\Windows\System32\cmd.exe"
        paths = _extract_file_paths(text)
        self.assertTrue(len(paths) > 0)

    def test_filter_generic_paths(self):
        paths = _extract_file_paths("C:\\")
        self.assertEqual(paths, [])

    def test_no_paths(self):
        self.assertEqual(_extract_file_paths("no paths here"), [])


class TestExtractIocsFromStrings(unittest.TestCase):
    """Verify combined IOC extraction pipeline."""

    def test_all_ioc_types_returned(self):
        strings = ["192.168.1.1", "http://evil.com/test", "evil.xyz",
                    r"HKEY_LOCAL_MACHINE\Software\Evil", r"C:\malware\bad.exe"]
        iocs = _extract_iocs_from_strings(strings)
        self.assertIn("ips", iocs)
        self.assertIn("domains", iocs)
        self.assertIn("urls", iocs)
        self.assertIn("registry_keys", iocs)
        self.assertIn("file_paths", iocs)

    def test_empty_strings(self):
        iocs = _extract_iocs_from_strings([])
        self.assertEqual(iocs["ips"], [])
        self.assertEqual(iocs["domains"], [])
        self.assertEqual(iocs["urls"], [])

    def test_mixed_content(self):
        strings = ["connecting to 193.42.11.23:443", "http://193.42.11.23/stage2.ps1"]
        iocs = _extract_iocs_from_strings(strings)
        self.assertIn("193.42.11.23", iocs["ips"])


# ==========================================================================
#  Test: _detect_file_type  (magic bytes)
# ==========================================================================
class TestDetectFileType(unittest.TestCase):
    """Verify magic-byte file type detection (now returns tuple)."""

    def test_pe_executable(self):
        ft, mis = _detect_file_type(b"MZ" + b"\x00" * 100, "test.exe")
        self.assertEqual(ft, "Windows PE Executable")
        self.assertEqual(mis, "")  # extension matches

    def test_elf(self):
        ft, mis = _detect_file_type(b"\x7fELF" + b"\x00" * 100, "test")
        self.assertEqual(ft, "Linux ELF Executable")

    def test_pdf(self):
        ft, mis = _detect_file_type(b"%PDF-1.4" + b"\x00" * 100, "test.pdf")
        self.assertEqual(ft, "PDF Document")
        self.assertEqual(mis, "")  # extension matches magic

    def test_png(self):
        ft, mis = _detect_file_type(b"\x89PNG" + b"\x00" * 100, "img.png")
        self.assertEqual(ft, "PNG Image")

    def test_zip(self):
        ft, mis = _detect_file_type(b"PK" + b"\x00" * 100, "archive.zip")
        self.assertEqual(ft, "ZIP Archive (possibly JAR/APK/DOCX)")

    def test_unknown_fallback_to_extension(self):
        ft, mis = _detect_file_type(b"\xAA\xBB\xCC" + b"\x00" * 100, "malware.exe")
        self.assertIn("exe", ft.lower())

    def test_unknown_binary(self):
        ft, mis = _detect_file_type(b"\xAA\xBB\xCC" + b"\x00" * 100, "noext")
        self.assertEqual(ft, "Unknown Binary")

    def test_dll_extension_fallback(self):
        ft, mis = _detect_file_type(b"\xFF\xFF", "lib.dll")
        self.assertIn("DLL", ft)

    def test_bin_extension_fallback(self):
        ft, mis = _detect_file_type(b"\xFF\xFF", "data.bin")
        self.assertIn("Binary", ft)

    def test_magic_bytes_override_extension(self):
        # PDF magic bytes but .exe extension -> should detect as PDF, no mismatch for .exe
        ft, mis = _detect_file_type(b"%PDF-1.4" + b"\x00" * 100, "suspicious.exe")
        self.assertEqual(ft, "PDF Document")

    def test_mismatch_pdf_with_mz_bytes(self):
        """A .pdf file with MZ magic bytes should flag mismatch."""
        ft, mis = _detect_file_type(b"MZ" + b"\x00" * 100, "invoice.pdf")
        self.assertEqual(ft, "Windows PE Executable")
        self.assertIn("MISMATCH", mis)
        self.assertIn(".pdf", mis)

    def test_mismatch_png_with_mz_bytes(self):
        ft, mis = _detect_file_type(b"MZ" + b"\x00" * 100, "image.png")
        self.assertIn("MISMATCH", mis)

    def test_no_mismatch_for_unknown_ext(self):
        ft, mis = _detect_file_type(b"MZ" + b"\x00" * 100, "unknown_file")
        self.assertEqual(mis, "")

    def test_returns_tuple(self):
        result = _detect_file_type(b"test", "test.bin")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


# ==========================================================================
#  Test: _analyze_pe
# ==========================================================================
class TestAnalyzePE(unittest.TestCase):
    """Test PE analysis with mocked pefile and edge cases."""

    def test_invalid_pe_returns_warnings(self):
        """MZ header but invalid PE structure should return warnings, not crash."""
        result = _analyze_pe(b"MZ" + b"\x00" * 100)
        self.assertIn("is_pe", result)
        # Should either parse or warn — not crash
        self.assertIsInstance(result["pe_warnings"], list)

    def test_result_has_required_keys(self):
        result = _analyze_pe(b"MZ" + b"\x00" * 100)
        for key in ["is_pe", "compile_timestamp", "sections", "dangerous_imports",
                     "all_imports", "import_risk_score", "pe_warnings"]:
            self.assertIn(key, result, f"Missing key: {key}")


# ==========================================================================
#  Test: _select_interesting_strings
# ==========================================================================
class TestSelectInterestingStrings(unittest.TestCase):
    """Verify interesting string selection logic."""

    def test_iocs_prioritized(self):
        iocs = {"ips": ["10.0.0.1"], "domains": ["evil.com"], "urls": ["http://evil.com/x"],
                "registry_keys": [], "file_paths": []}
        strings = ["random string one", "another random string"]
        result = _select_interesting_strings(strings, iocs)
        values = [r["value"] for r in result]
        self.assertIn("10.0.0.1", values)
        self.assertIn("evil.com", values)

    def test_suspicious_keywords_detected(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        strings = ["cmd.exe /c whoami", "powershell -enc base64here", "normal string"]
        result = _select_interesting_strings(strings, iocs)
        types = [r["type"] for r in result]
        self.assertIn("Suspicious String", types)

    def test_max_count_respected(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        strings = [f"long interesting string number {i} for testing" for i in range(100)]
        result = _select_interesting_strings(strings, iocs, max_count=10)
        self.assertLessEqual(len(result), 10)

    def test_empty_input(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        result = _select_interesting_strings([], iocs)
        self.assertEqual(result, [])


# ==========================================================================
#  Test: _calculate_risk_score
# ==========================================================================
class TestCalculateRiskScore(unittest.TestCase):
    """Verify composite risk score calculation."""

    def test_zero_risk_benign_file(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(3.0, 0, iocs, pe, False)
        self.assertEqual(score, 0)

    def test_high_entropy_adds_points(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(7.9, 0, iocs, pe, False)
        self.assertEqual(score, 30)  # critical entropy contribution

    def test_import_risk_scaled(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(3.0, 100, iocs, pe, True)
        self.assertEqual(score, 40)  # 100 * 40 // 100 = 40

    def test_iocs_add_points(self):
        iocs = {"ips": ["1.1.1.1"] * 11, "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(3.0, 0, iocs, pe, False)
        self.assertEqual(score, 15)  # >10 IOCs

    def test_suspicious_timestamp_adds_points(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": True, "sections": []}
        score = _calculate_risk_score(3.0, 0, iocs, pe, False)
        self.assertEqual(score, 10)

    def test_suspicious_section_adds_points(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": [{"suspicious": True, "name": ".upx"}]}
        score = _calculate_risk_score(3.0, 0, iocs, pe, False)
        self.assertEqual(score, 5)

    def test_max_cap_at_100(self):
        iocs = {"ips": ["1.1.1.1"] * 20, "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": True, "sections": [{"suspicious": True, "name": ".x"}]}
        score = _calculate_risk_score(7.9, 100, iocs, pe, True)
        self.assertLessEqual(score, 100)

    def test_combined_signals(self):
        """Elevated entropy + some IOCs + imports should sum correctly."""
        iocs = {"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"], "domains": [], "urls": [],
                "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(6.5, 50, iocs, pe, True)
        # entropy 6.5 -> 10, import 50 -> 20, IOCs 3 -> 5  = 35
        self.assertEqual(score, 35)

    def test_file_type_mismatch_adds_15(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(3.0, 0, iocs, pe, False, file_type_mismatch=True)
        self.assertEqual(score, 15)

    def test_tiny_pe_adds_5(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"compile_timestamp_suspicious": False, "sections": []}
        score = _calculate_risk_score(3.0, 0, iocs, pe, True, size_bytes=1024)
        self.assertEqual(score, 5)


# ==========================================================================
#  Test: _generate_verdict
# ==========================================================================
class TestGenerateVerdict(unittest.TestCase):
    """Verify human-readable verdict generation."""

    def test_minimal_risk_verdict(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"dangerous_imports": [], "compile_timestamp_suspicious": False, "sections": []}
        verdict = _generate_verdict("Unknown Binary", 3.0, "Normal", 5, pe, iocs, False)
        self.assertIn("MINIMAL RISK", verdict)

    def test_critical_risk_verdict(self):
        iocs = {"ips": ["1.1.1.1"], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"dangerous_imports": [{"name": "CreateRemoteThread", "category": "Process Injection", "score": 35}],
              "compile_timestamp_suspicious": True, "compile_timestamp": "2089-01-01 00:00:00 UTC",
              "sections": [{"name": ".upx", "suspicious": True}]}
        verdict = _generate_verdict("Windows PE Executable", 7.5, "HIGH", 80, pe, iocs, True)
        self.assertIn("CRITICAL RISK", verdict)
        self.assertIn("Process Injection", verdict)
        self.assertIn("forged", verdict)

    def test_entropy_warning_in_verdict(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"dangerous_imports": [], "compile_timestamp_suspicious": False, "sections": []}
        verdict = _generate_verdict("Unknown Binary", 7.5, "HIGH", 25, pe, iocs, False)
        self.assertIn("packed or encrypted", verdict)

    def test_ioc_count_in_verdict(self):
        iocs = {"ips": ["1.1.1.1", "2.2.2.2"], "domains": ["evil.com"], "urls": [],
                "registry_keys": [], "file_paths": []}
        pe = {"dangerous_imports": [], "compile_timestamp_suspicious": False, "sections": []}
        verdict = _generate_verdict("Unknown Binary", 3.0, "Normal", 5, pe, iocs, False)
        self.assertIn("2 IP(s)", verdict)
        self.assertIn("1 domain(s)", verdict)

    def test_verdict_is_string(self):
        iocs = {"ips": [], "domains": [], "urls": [], "registry_keys": [], "file_paths": []}
        pe = {"dangerous_imports": [], "compile_timestamp_suspicious": False, "sections": []}
        verdict = _generate_verdict("test", 0.0, "Low", 0, pe, iocs, False)
        self.assertIsInstance(verdict, str)


# ==========================================================================
#  Test: analyze_binary (main public function)
# ==========================================================================
class TestAnalyzeBinary(unittest.TestCase):
    """Integration tests for the main analyze_binary function."""

    def test_returns_dict(self):
        result = analyze_binary(b"test data", "test.bin")
        self.assertIsInstance(result, dict)

    def test_required_keys_present(self):
        """Verify ALL keys required by the pipeline contract are present."""
        result = analyze_binary(b"test data", "test.bin")
        required_keys = [
            "filename", "input_type", "file_type",
            "md5", "sha1", "sha256",
            "size_bytes", "entropy", "entropy_verdict",
            "is_pe", "compile_timestamp",
            "dangerous_imports", "import_risk_score",
            "iocs", "interesting_strings",
            "risk_score",
        ]
        for key in required_keys:
            self.assertIn(key, result, f"Missing required key: {key}")

    def test_input_type_always_binary(self):
        result = analyze_binary(b"test", "test.bin")
        self.assertEqual(result["input_type"], "binary")

    def test_none_input_doesnt_crash(self):
        result = analyze_binary(None, "none.bin")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["input_type"], "binary")

    def test_empty_bytes(self):
        result = analyze_binary(b"", "empty.bin")
        self.assertEqual(result["size_bytes"], 0)
        self.assertEqual(result["risk_score"], 0)

    def test_iocs_dict_structure(self):
        result = analyze_binary(b"test connecting to 10.0.0.1 done", "test.bin")
        iocs = result["iocs"]
        self.assertIn("ips", iocs)
        self.assertIn("domains", iocs)
        self.assertIn("urls", iocs)
        self.assertIn("registry_keys", iocs)
        self.assertIn("file_paths", iocs)

    def test_ioc_extraction_from_binary(self):
        data = b"connect to 193.42.11.23 and http://evil.ru/payload.exe for staging"
        result = analyze_binary(data, "sample.bin")
        self.assertIn("193.42.11.23", result["iocs"]["ips"])
        self.assertTrue(any("evil.ru" in u for u in result["iocs"]["urls"]))

    def test_mz_header_detected_as_pe(self):
        result = analyze_binary(b"MZ" + b"\x00" * 200, "test.exe")
        self.assertTrue(result["is_pe"])

    def test_non_pe_detected(self):
        result = analyze_binary(b"just some text data", "test.txt")
        self.assertFalse(result["is_pe"])

    def test_correct_filename_returned(self):
        result = analyze_binary(b"test", "myfile.dll")
        self.assertEqual(result["filename"], "myfile.dll")

    def test_correct_size_bytes(self):
        data = b"exactly 26 bytes of data!!"
        result = analyze_binary(data, "test.bin")
        self.assertEqual(result["size_bytes"], len(data))

    def test_eicar_test_file(self):
        """EICAR test file — core demo file #1. Should analyze and flag eicar_detected."""
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        result = analyze_binary(eicar, "eicar_test.txt")
        self.assertEqual(result["input_type"], "binary")
        self.assertIsInstance(result["entropy"], float)
        self.assertIsInstance(result["risk_score"], int)
        self.assertTrue(result["eicar_detected"])

    def test_eicar_not_detected_in_normal_file(self):
        result = analyze_binary(b"just a normal file", "test.bin")
        self.assertFalse(result["eicar_detected"])

    def test_file_type_mismatch_field(self):
        """A .pdf with MZ bytes should populate file_type_mismatch."""
        result = analyze_binary(b"MZ" + b"\x00" * 200, "invoice.pdf")
        self.assertIn("MISMATCH", result["file_type_mismatch"])
        self.assertIn("MISMATCH", result["verdict"])

    def test_no_mismatch_for_exe(self):
        result = analyze_binary(b"MZ" + b"\x00" * 200, "malware.exe")
        self.assertEqual(result["file_type_mismatch"], "")

    def test_wide_string_extraction(self):
        """UTF-16LE encoded string should be extracted."""
        wide = "HelloWorld".encode("utf-16-le")
        data = b"\x00" * 50 + wide + b"\x00" * 50
        result = analyze_binary(data, "test.bin")
        # Should find the wide string in extracted strings or interesting_strings
        all_vals = [s["value"] if isinstance(s, dict) else s for s in result["interesting_strings"]]
        # Also check that extraction works at lower level
        from analyzer import _extract_strings
        strings = _extract_strings(data)
        self.assertIn("HelloWorld", strings)

    def test_demo_firewall_log(self):
        """Demo file #3 — firewall log. Should extract the C2 IP."""
        log = (
            b"2026-03-05 03:47:22 OUTBOUND TCP 192.168.1.105:54821 -> 193.42.11.23:443 ALLOW 2847293 bytes\n"
            b"2026-03-05 03:47:23 OUTBOUND TCP 192.168.1.105:54822 -> 193.42.11.23:443 ALLOW 1923847 bytes\n"
        )
        result = analyze_binary(log, "firewall_log.txt")
        self.assertIn("193.42.11.23", result["iocs"]["ips"])

    def test_large_binary_doesnt_crash(self):
        """Simulate a large file (100KB of random-ish data)."""
        import random
        random.seed(99)
        data = bytes(random.randint(0, 255) for _ in range(100_000))
        result = analyze_binary(data, "big.bin")
        self.assertIsInstance(result, dict)
        self.assertGreater(result["entropy"], 7.0)

    def test_verdict_field_present(self):
        result = analyze_binary(b"test", "test.bin")
        self.assertIn("verdict", result)
        self.assertIsInstance(result["verdict"], str)

    def test_hash_correctness(self):
        data = b"verify my hashes"
        result = analyze_binary(data, "test.bin")
        self.assertEqual(result["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())


# ==========================================================================
#  Test: Edge cases & robustness
# ==========================================================================
class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error resilience."""

    def test_binary_with_null_bytes(self):
        data = b"\x00" * 1000
        result = analyze_binary(data, "nulls.bin")
        self.assertIsInstance(result, dict)
        self.assertAlmostEqual(result["entropy"], 0.0, places=1)

    def test_unicode_filename(self):
        result = analyze_binary(b"test", "文件.exe")
        self.assertEqual(result["filename"], "文件.exe")

    def test_filename_with_no_extension(self):
        result = analyze_binary(b"test", "noextension")
        self.assertIsInstance(result["file_type"], str)

    def test_very_short_file(self):
        result = analyze_binary(b"A", "tiny.bin")
        self.assertEqual(result["size_bytes"], 1)

    def test_pe_format_error_handled(self):
        """MZ header followed by garbage should not crash."""
        data = b"MZ" + bytes(range(256)) * 4
        result = analyze_binary(data, "corrupt.exe")
        self.assertIsInstance(result, dict)
        self.assertTrue(result["is_pe"])

    def test_dangerous_imports_constant_structure(self):
        """Verify the DANGEROUS_IMPORTS dict has correct value types."""
        for name, (category, score) in DANGEROUS_IMPORTS.items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(category, str)
            self.assertIsInstance(score, int)
            self.assertGreater(score, 0)

    def test_benign_domains_are_lowercase(self):
        for d in BENIGN_DOMAINS:
            self.assertEqual(d, d.lower(), f"Benign domain {d} should be lowercase")

    def test_magic_bytes_table_completeness(self):
        """Verify key file types are in the magic bytes table."""
        magic_types = set(MAGIC_BYTES.values())
        self.assertIn("Windows PE Executable", magic_types)
        self.assertIn("Linux ELF Executable", magic_types)
        self.assertIn("PDF Document", magic_types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
