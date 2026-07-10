import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_module(alias: str, relpath: str):
    """Load a module by file path under a unique alias.

    Both services have a package named `app`, so importing them the normal
    way collides in sys.modules.
    """
    spec = importlib.util.spec_from_file_location(alias, ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module
