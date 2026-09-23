"""
M10.5 Tests — End-to-End full pipeline validation via Orchestrator and CLI.
"""
import pytest
import os
import tempfile
import subprocess
from pathlib import Path

from securemailscope.core.orchestrator import Orchestrator


BASE = Path(__file__).parent.parent / "tests/robustness/fixtures/pcaps"

def get_test_fixture(name="clean_baseline.pcap"):
    path = BASE / name
    return str(path) if path.exists() else None


def test_orchestrator_end_to_end_analysis():
    pcap = get_test_fixture("smtp_weak_deprecated.pcap")
    if not pcap:
        pytest.skip("Fixture not found")

    orc = Orchestrator()
    posture, meta = orc.analyze(pcap)

    # Validate pipeline ran correctly
    assert posture.total_sessions > 0
    assert posture.tls_sessions > 0

    # smtp_weak_deprecated should trigger specific findings
    assert posture.findings_count > 0
    found_deprecated_tls = False
    for group in posture.root_cause_groups.values():
        if "Deprecated TLS Protocol Version" in group["root_issue"]:
            found_deprecated_tls = True

    assert found_deprecated_tls, "Pipeline failed to detect deprecated TLS on weak pcap."

    # Validate overall shape
    assert 0 <= posture.overall_score < 100


def test_cli_integration_with_actual_pipeline():
    """Verify the CLI successfully processes a real PCAP and produces reports."""
    pcap = get_test_fixture("smtp_starttls_tls13_secure.pcap")
    if not pcap:
        pytest.skip("Fixture not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Run CLI process
        cli_path = Path(__file__).parent.parent / "securemailscope/cli.py"
        result = subprocess.run(
            ["python", str(cli_path), "analyze", pcap, "--output-dir", tmpdir, "--json", "--html"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"CLI execution failed: {result.stderr}"

        # Verify output files
        json_files = list(Path(tmpdir).glob("*.json"))
        html_files = list(Path(tmpdir).glob("*.html"))

        assert len(json_files) == 1
        assert len(html_files) == 1

        # Verify CLI terminal summary
        assert "Security Posture:" in result.stdout
        assert "Good" in result.stdout or "88/100" in result.stdout
        assert "Email sessions: 1" in result.stdout


def test_orchestrator_handles_corrupt_files():
    with tempfile.NamedTemporaryFile("w+", suffix=".pcap", delete=False) as f:
        f.write("not a pcap file")
        name = f.name

    try:
        orc = Orchestrator()
        with pytest.raises(ValueError):
            orc.analyze(name)
    finally:
        os.unlink(name)
