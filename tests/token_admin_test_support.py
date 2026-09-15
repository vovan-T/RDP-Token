import importlib.util
import sys
from pathlib import Path


def load_diagnostic_cli():
    token_admin = Path(__file__).resolve().parents[1] / "token-admin"
    sys.path.insert(0, str(token_admin))
    path = token_admin / "core" / "diagnostic_cli.py"
    spec = importlib.util.spec_from_file_location("rdp_token_diagnostic_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
