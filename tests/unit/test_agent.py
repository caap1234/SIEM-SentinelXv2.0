import os
import tempfile
import subprocess
import pytest

AGENT_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../agent/sentinelx-agent.sh"))

def test_agent_script_syntax():
    """Verify bash syntax of sentinelx-agent.sh."""
    result = subprocess.run(["bash", "-n", AGENT_SCRIPT], capture_output=True, text=True)
    assert result.returncode == 0, f"Syntax error in agent script: {result.stderr}"

def test_agent_environment_defaults():
    """Verify default safety values in sentinelx-agent.sh environment defaults."""
    with open(AGENT_SCRIPT, "r") as f:
        content = f.read()

    assert 'RESET_ON_BACKEND_DOWN="${SENTINELX_RESET_ON_BACKEND_DOWN:-0}"' in content
    assert 'RESET_ON_SEND_FAILURE="${SENTINELX_RESET_ON_SEND_FAILURE:-0}"' in content

def test_agent_state_file_creation(tmp_path):
    """Test agent state tracking function generates valid agent_state.json."""
    state_dir = tmp_path / "state"
    spool_dir = tmp_path / "spool"
    tmp_dir = tmp_path / "tmp"
    lock_file = tmp_path / "lock" / "agent.lock"
    
    state_dir.mkdir()
    spool_dir.mkdir()
    tmp_dir.mkdir()
    (tmp_path / "lock").mkdir()

    env = os.environ.copy()
    env["STATE_DIR"] = str(state_dir)
    env["SPOOL_DIR"] = str(spool_dir)
    env["TMP_DIR"] = str(tmp_dir)
    env["SENTINELX_LOCK_FILE"] = str(lock_file)
    env["ENV_FILE"] = "/dev/null"
    env["SENTINELX_INGEST_URL"] = "http://127.0.0.1:59999/invalid_test_endpoint"
    env["SENTINELX_API_KEY"] = "test-key"
    env["SENTINELX_MAX_SECONDS_PER_RUN"] = "5"

    result = subprocess.run(["bash", AGENT_SCRIPT], env=env, capture_output=True, text=True)
    
    state_file = state_dir / "agent_state.json"
    assert state_file.exists(), f"agent_state.json should be created. Output: {result.stdout}\nError: {result.stderr}"
    
    state_content = state_file.read_text()
    assert '"state":' in state_content
    assert '"offline"' in state_content or '"healthy"' in state_content
