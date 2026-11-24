"""Exception types raised by the renef Python client."""


class RenefError(Exception):
    """Base class for every error raised by this package."""


class RenefConnectionError(RenefError):
    """The connection to renef_server could not be made, or was lost."""


class RenefTimeoutError(RenefError):
    """No reply (or no end of reply) arrived in time.

    ``partial`` holds whatever output had been received until then.
    """

    def __init__(self, message, partial=""):
        super().__init__(message)
        self.partial = partial


class CommandError(RenefError):
    """renef_server answered a command with ``ERROR: ...``."""

    def __init__(self, message, output=""):
        super().__init__(message)
        self.output = output


class LuaError(RenefError):
    """Lua code run in the target failed (syntax error or runtime error)."""


class HookInstallError(RenefError):
    """A hook could not be installed (bad target, table full, ...)."""


class SessionClosedError(RenefError):
    """The session was used after close(), or its target was replaced."""
