from threatlens.core.security import InvalidToken


class IdentityError(Exception):
    """Base class; the API maps subclasses to HTTP status codes."""


class UnknownRole(IdentityError):
    pass


class UnknownAgent(IdentityError):
    pass


class AgentExists(IdentityError):
    pass


class InvalidAmendment(IdentityError):
    pass


class DelegationDenied(IdentityError):
    pass


class AgentQuarantined(IdentityError):
    pass


class TokenRevoked(InvalidToken):
    pass
