import subprocess
import time
import pytest
import json
import os
import signal
from pathlib import Path

@pytest.fixture(scope="module")
def defender_server():
    """Starts the defender server in the background."""
    port = 8889  # Use a different port for tests
    report_file = "test_defender_report.json"
    
    # Ensure any old report is gone
    if os.path.exists(report_file):
        os.remove(report_file)
        
    cmd = ["python3", "evasion/defender_server.py", "--port", str(port), "--output", report_file]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for server to start
    time.sleep(2)
    
    yield f"http://localhost:{port}"
    
    # Stop the server (triggers report generation)
    proc.send_signal(signal.SIGINT)
    proc.wait(timeout=5)
    
    if os.path.exists(report_file):
        with open(report_file, 'r') as f:
            report = json.load(f)
            # print(f"\nDefender Report: {len(report)} requests logged")

def test_audit_against_defender(defender_server):
    """Run full audit against the defender server."""
    cmd = ["python3", "tit-for-tat.py", "audit", "--target", defender_server, "--cms-scan", "--comments-analysis"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "SECURITY AUDIT SUMMARY" in result.stdout
    assert "Comment Platform Analysis" in result.stdout

def test_stealth_forensic_against_defender(defender_server):
    """Run forensic fetch with stealth against the defender server."""
    cmd = ["python3", "tit-for-tat.py", "forensic", "--url", defender_server, "--stealth", "--entropy-score"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "Forensic fetch" in result.stdout
    assert "Behavioral Entropy Report" in result.stdout
    assert "Stealth: using browser profile" in result.stdout

def test_canary_scan_against_defender(defender_server):
    """Run canary scan against the defender server."""
    cmd = ["python3", "tit-for-tat.py", "canary-scan", "--url", defender_server]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "CANARY TOKEN SCAN RESULTS" in result.stdout
    assert "ZERO_WIDTH_CHARS (HIGH)" in result.stdout
    assert "CSS_HIDDEN_TEXT (MEDIUM)" in result.stdout
