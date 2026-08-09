import importlib.util
import os
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

MIGRATION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../alembic/versions/e50000000001_phase5_enterprise_transactional_schema.py")
)


def test_alembic_script_directory_loads():
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)
    revisions = [sc.revision for sc in script.walk_revisions()]
    assert "e50000000001" in revisions


def test_phase5_migration_revision_metadata():
    spec = importlib.util.spec_from_file_location("mig_phase5", MIGRATION_PATH)
    mig_phase5 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig_phase5)

    assert mig_phase5.revision == "e50000000001"
    assert mig_phase5.down_revision == "01410dd9cec5"
