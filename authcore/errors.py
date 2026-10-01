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
