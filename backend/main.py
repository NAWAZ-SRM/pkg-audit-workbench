from pathlib import Path
import sys

try:
    from .api.main import app as app
except ImportError:
    repo_root = Path(__file__).resolve().parent.parent
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    from backend.api.main import app as app
