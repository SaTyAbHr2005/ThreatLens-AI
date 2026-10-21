"""M1 Identity & Role Registry: Role Contracts, agents, tokens, amendments, delegation."""

from .contracts import apply_changes, load_contract_file, load_role_dir
from .drafting import draft_contract
from .errors import (
    AgentExists,
    AgentQuarantined,
    DelegationDenied,
    IdentityError,
    InvalidAmendment,
    TokenRevoked,
    UnknownAgent,
    UnknownRole,
)
from .registry import AgentToken, IssuedToken, Registry
from .store import MemoryRegistryStore, MongoRegistryStore

__all__ = [
    "AgentExists",
    "AgentQuarantined",
    "AgentToken",
    "DelegationDenied",
    "IdentityError",
    "InvalidAmendment",
    "IssuedToken",
    "MemoryRegistryStore",
    "MongoRegistryStore",
    "Registry",
    "TokenRevoked",
    "UnknownAgent",
    "UnknownRole",
    "apply_changes",
    "draft_contract",
    "load_contract_file",
    "load_role_dir",
]
