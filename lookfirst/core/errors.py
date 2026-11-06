"""Errors that lookfirst can explain to the user in plain English."""


class LookfirstError(Exception):
    """A problem with a plain-English message, and optionally a hint for what to do."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class TargetError(LookfirstError):
    """We couldn't understand or find the target."""


class FetchError(LookfirstError):
    """We couldn't download the target or its details."""


class UnsafeArchiveError(LookfirstError):
    """An archive was too big or too damaged to unpack safely."""


class CouldntCheckError(LookfirstError):
    """The main thing to check couldn't be read, so no verdict would mean anything."""
