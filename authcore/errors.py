class AuthError(Exception):
    """Base class for all authentication failures.

    Every concrete rejection is a distinct, meaningful error so callers never
    have to collapse different failure modes into a generic network error.
    """


class InvalidCredentialsError(AuthError):
    """Username/password pair does not match."""


class AccountDisabledError(AuthError):
    """The account has been deactivated."""


class MalformedTokenError(AuthError):
    """The credential string does not have the expected shape."""


class InvalidTokenError(AuthError):
    """Well-formed credential that is unknown to this server."""


class TokenExpiredError(AuthError):
    """Credential was valid once but its lifetime is over."""


class TokenRevokedError(AuthError):
    """Credential (or its session/family) has been explicitly revoked."""


class TokenReuseDetectedError(TokenRevokedError):
    """A consumed refresh credential was presented again.

    Presenting this error means the entire refresh family has been revoked,
        which is the correct response to a stolen/old refresh credential.
    """


class ChainSupersededError(TokenRevokedError):
    """A credential from a chain retired by a planned device rotation.

    The old chain was not fused for suspected compromise: it retired on a
    fixed schedule. Refresh attempts are always refused; in-flight access
    requests are accepted only until the wind-down window shown when the
    rotation was announced closes. The new chain of the same device is
    never affected by the late arrival of such a request.
    """


class ChainWoundDownError(TokenRevokedError):
    """An in-flight request from a retired chain arrived after wind-down.

    The pre-announced completion window for the old chain has closed, so
    even an otherwise valid old access credential is now refused.
    """
