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


class CredentialSupersededError(TokenRevokedError):
    """A refresh credential of a credential generation that was retired.

    Raised on a *planned* device credential rollover. The old login chain can
    no longer create new refreshes, but the decision is a policy rejection of
    a retired generation -- not a reuse circuit break -- so the new chain of
    the same device is never frozen just because an old request arrived late.
    """


class DeviceFrozenError(TokenRevokedError):
    """The device is under an emergency compromise freeze.

    All outstanding authorization of the device is revoked, including the
    wind-down access tokens a planned rollover had left valid.
    """


class RolloverPlanError(AuthError):
    """A staged multi-device rollover plan cannot proceed as requested.

    Raised for unknown plans/batches, batches that were not explicitly
    approved, batches that were already executed, and plans whose declared
    constraints (e.g. minimum available devices) are impossible by
    construction. A per-device failure inside a batch is *not* this error:
    it is recorded in the batch result and never freezes other devices.
    """
