"""Distinct failure types so callers never collapse refusals into "network error"."""


class AuthError(Exception):
    """Base class for every authentication/credential failure."""


class InvalidCredentialsError(AuthError):
    """Username unknown or password incorrect."""


class TokenFormatError(AuthError):
    """The presented credential does not have a syntactically valid token shape."""


class InvalidTokenError(AuthError):
    """Well-formed token that the server has never issued or no longer knows."""


class TokenExpiredError(AuthError):
    """Base class for expired credentials."""


class AccessTokenExpiredError(TokenExpiredError):
    """The access credential is past its lifetime."""


class RefreshTokenExpiredError(TokenExpiredError):
    """The renewal credential is past its lifetime."""


class RevokedError(AuthError):
    """The credential (or its renewal family/session) was explicitly revoked."""


class AccountDisabledError(AuthError):
    """The account backing the credential was deactivated."""


class TokenReuseError(RevokedError):
    """A rotated renewal credential was presented again; family revoked."""

    def __init__(self, message, record_id=None):
        super().__init__(message)
        self.record_id = record_id
