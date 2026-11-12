"""lookfirst: check code from strangers before you or your AI agent runs it."""


def __getattr__(name: str) -> str:
    # The version is looked up only when asked for: importlib.metadata takes about 28 ms
    # to import, and the hook's fast path never needs it.
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            value = version("lookfirst")
        except PackageNotFoundError:  # running from a source tree that isn't installed
            value = "0.0.0+unknown"
        globals()["__version__"] = value
        return value
    raise AttributeError(f"module 'lookfirst' has no attribute {name!r}")
