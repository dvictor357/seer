"""Shared test setup: put scripts/ on the path and point SEER_HOME at a temp dir
so the user's ~/.config/seer (RPCs, API keys, caches) never leaks into a test."""
import atexit
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")

SEER_HOME = tempfile.mkdtemp(prefix="seer-test-")
atexit.register(shutil.rmtree, SEER_HOME, True)
os.environ["SEER_HOME"] = SEER_HOME
for _key in ("ETHERSCAN_API_KEY", "LOG_BUDGET", "RPC_URL"):
    os.environ.pop(_key, None)

if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


def clean_env(**extra):
    """Environment for a subprocess: no user config, no keys, plus `extra`."""
    env = {k: v for k, v in os.environ.items() if k not in ("ETHERSCAN_API_KEY", "LOG_BUDGET", "RPC_URL")}
    env["SEER_HOME"] = SEER_HOME
    env.update(extra)
    return env
