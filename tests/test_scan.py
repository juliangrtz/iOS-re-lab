import os
import pytest

from core.scan import MachOScanner


SAMPLE_PATH = os.path.join(os.path.dirname(
    __file__), "binaries", "IOSSecuritySuite")


def _sample_file_path():
    if os.path.isfile(SAMPLE_PATH):
        return SAMPLE_PATH
    if os.path.isdir(SAMPLE_PATH):
        for fname in os.listdir(SAMPLE_PATH):
            candidate = os.path.join(SAMPLE_PATH, fname)
            if os.path.isfile(candidate):
                return candidate
    return None


def test_scan_real_macho():
    try:
        import lief
    except Exception:
        pytest.skip(
            "lief is not installed!")

    sample = _sample_file_path()
    if not sample or not os.path.exists(sample):
        pytest.skip(
            f"Failed to load IOSSecuritySuite")

    strings = {
        "SUSPICIOUS_IMPORTS": {"ANTI_DEBUG": ["ptrace", "sysctl"]},
        "JAILBREAK_STRINGS": ["Cydia", "Substrate"],
    }

    logs = []

    def logger(msg, level="info"):
        logs.append((level, msg))

    scanner = MachOScanner(strings_dict=strings)

    results = scanner.analyze(
        sample, syscall_map_path=None, out_path=None, verbose=False, run_yara=False)

    assert isinstance(results, list), "analyze() should return a list!"
    assert len(
        results) >= 1, "Expecting at least one entry in the resulting list!"

    entry = results[0]
    assert "binary" in entry
    assert "cpu" in entry
    assert "pie" in entry
    assert "imports" in entry and isinstance(entry["imports"], list)
    assert "syscalls" in entry and isinstance(entry["syscalls"], list)

    assert isinstance(entry["cpu"], str) and entry["cpu"].strip() != ""

    error_logs = [m for lvl, m in logs if lvl.lower() in ("error", "warn")]
    assert isinstance(error_logs, list)
