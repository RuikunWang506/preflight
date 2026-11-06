"""lookfirst: check code from strangers before you or your AI agent runs it."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lookfirst")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
