import json
import os
import subprocess
import pytest

METRICS_SCRIPT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../agent/sentinelx-agent-metrics.sh")
)


def test_metrics_script_syntax():
    """Verify bash syntax of sentinelx-agent-metrics.sh."""
    result = subprocess.run(["bash", "-n", METRICS_SCRIPT], capture_output=True, text=True)
    assert result.returncode == 0, f"Syntax error in metrics script: {result.stderr}"


def test_collect_host_metrics_disabled_by_default():
    """When SENTINELX_COLLECT_METRICS is not 1, script should produce empty output."""
    env = os.environ.copy()
    env["SENTINELX_COLLECT_METRICS"] = "0"

    result = subprocess.run(["bash", METRICS_SCRIPT], env=env, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_collect_host_metrics_enabled_produces_json(tmp_path):
    """When SENTINELX_COLLECT_METRICS=1, script should produce valid JSON metrics payload."""
    spool_dir = tmp_path / "spool"
    state_dir = tmp_path / "state"
    spool_dir.mkdir()
    state_dir.mkdir()

    # Create dummy spool file and agent_state.json
    (spool_dir / "test_chunk.part.gz").write_text("dummy payload")
    (state_dir / "agent_state.json").write_text('{"state":"healthy","pid":1234}')

    env = os.environ.copy()
    env["SENTINELX_COLLECT_METRICS"] = "1"
    env["SPOOL_DIR"] = str(spool_dir)
    env["STATE_DIR"] = str(state_dir)

    result = subprocess.run(["bash", METRICS_SCRIPT], env=env, capture_output=True, text=True)
    assert result.returncode == 0, f"Script failed: {result.stderr}"

    output = result.stdout.strip()
    assert len(output) > 0, "Metrics script should output JSON"

    # Verify JSON structure
    data = json.loads(output)
    assert "@timestamp" in data
    assert "host" in data
    assert "event" in data
    assert data["event"]["kind"] == "metric"
    assert data["event"]["dataset"] == "sentinelx.metrics.system"
    assert "agent" in data
    assert data["agent"]["spool_files"] == 1
    assert data["agent"]["state"]["state"] == "healthy"
