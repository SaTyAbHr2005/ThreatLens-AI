"""M1 Identity & Role Registry.

Holds every Role Contract version, every agent, and token state in memory so
the gateway's per-call checks never wait on the database; writes go through to
the RegistryStore.

ponytail: in-memory state is per process. Fine for one Render instance; with
several gateway replicas, revocations need a shared store (Redis pub/sub, see
PRODUCTION.md §2).
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from threatlens.core.config import Settings, get_settings
from threatlens.core.schemas import Agent, AgentStatus, RoleAmendment, RoleContract, utcnow
from threatlens.core.security import AUD_GATEWAY, issue_token, verify_token

from .contracts import apply_changes, load_role_dir, sign, verify_signature
from .errors import (
    AgentExists,
    AgentQuarantined,
    DelegationDenied,
    InvalidAmendment,
    TokenRevoked,
    UnknownAgent,
    UnknownRole,
)

log = logging.getLogger(__name__)

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SIGNER_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AgentToken(BaseModel):
    """Verified claims of an agent (or delegated) token."""

    agent_id: str
    role: str
    role_version: int
    scopes: list[str]  # tools this token may call
    chain: list[str]  # root → … → this agent
    depth: int
    root_role: str
    jti: str
    expires_at: datetime
    act: dict[str, Any] | None = None  # RFC 8693 actor chain, delegated tokens only


class IssuedToken(BaseModel):
    token: str
    claims: AgentToken


class _Version(BaseModel):
    contract: RoleContract
    amendment_id: str | None = None
    expires_at: datetime | None = None


class Registry:
    def __init__(self, store: Any, settings: Settings | None = None) -> None:
        self.store = store
        self.settings = settings or get_settings()
        self._versions: dict[str, dict[int, _Version]] = {}
        self._agents: dict[str, Agent] = {}
        self._amendments: list[RoleAmendment] = []
        self._revoked: dict[str, datetime] = {}
        self._live: dict[str, AgentToken] = {}  # issued, not yet expired

    # ------------------------------------------------------------ startup

    async def load(self, roles_dir: Path | None = None) -> None:
        """Load signed versions from the store, then seed newer YAML contracts."""
        key = self.settings.jwt_signing_key
        for doc in await self.store.load_contract_versions():
            if not verify_signature(doc["contract"], doc.get("signature"), key):
                log.error("ignoring tampered contract %s v%s", doc.get("role"), doc.get("version"))
                continue
            self._put_version(_Version.model_validate(doc))

        for contract in load_role_dir(roles_dir or self.settings.roles_dir):
            known = self._versions.get(contract.role, {})
            if not known or max(known) < contract.version:
                await self._save_version(_Version(contract=contract))

        self._amendments = [
            a for a in await self.store.load_amendments() if verify_signature(_amendment_body(a), a.signature, key)
        ]
        self._agents = {a.agent_id: a for a in await self.store.load_agents()}
        self._revoked = await self.store.load_revoked()

    # ------------------------------------------------------------ contracts

    def contract(self, role: str, version: int | None = None) -> RoleContract:
        versions = self._versions.get(role)
        if not versions:
            raise UnknownRole(role)
        if version is not None:
            if version not in versions:
                raise UnknownRole(f"{role} v{version}")
            return versions[version].contract
        now = utcnow()
        # Latest version whose amendment hasn't expired.
        # ponytail: versions stacked on an expired amendment keep its changes; re-amend if that matters.
        for v in sorted(versions, reverse=True):
            exp = versions[v].expires_at
            if exp is None or exp > now:
                return versions[v].contract
        return versions[min(versions)].contract

    def roles(self) -> list[RoleContract]:
        return [self.contract(r) for r in sorted(self._versions)]

    def amendments(self, role: str | None = None) -> list[RoleAmendment]:
        return [a for a in self._amendments if role is None or a.role == role]

    async def amend(
        self,
        role: str,
        changes: dict[str, Any],
        reason: str,
        signer: str,
        expires_at: datetime | None = None,
    ) -> RoleAmendment:
        """Apply a human-approved change, creating the next contract version."""
        # Agent ids can't contain "@", so requiring an email also means agents can't sign.
        if not SIGNER_RE.match(signer):
            raise InvalidAmendment("signer must be a person's email address")
        if not reason.strip():
            raise InvalidAmendment("a reason is required")
        current = self.contract(role)
        latest = max(self._versions[role])
        new = apply_changes(self.contract(role, latest), changes)

        amendment = RoleAmendment(
            role=role,
            from_version=current.version,
            to_version=new.version,
            diff=changes,
            reason=reason,
            signer=signer,
            expires_at=expires_at,
        )
        amendment.signature = sign(_amendment_body(amendment), self.settings.jwt_signing_key)
        await self.store.save_amendment(amendment)
        await self._save_version(_Version(contract=new, amendment_id=amendment.id, expires_at=expires_at))
        self._amendments.append(amendment)
        return amendment

    # ------------------------------------------------------------ agents

    async def create_agent(self, agent_id: str, role: str, owner: str) -> Agent:
        if not AGENT_ID_RE.match(agent_id):
            raise ValueError("agent_id must be 3-64 chars of lowercase letters, digits and hyphens")
        if agent_id in self._agents:
            raise AgentExists(agent_id)
        contract = self.contract(role)
        agent = Agent(agent_id=agent_id, role=role, role_version=contract.version, owner=owner)
        await self.store.save_agent(agent)
        self._agents[agent_id] = agent
        return agent

    def agent(self, agent_id: str) -> Agent:
        try:
            return self._agents[agent_id]
        except KeyError:
            raise UnknownAgent(agent_id) from None

    def agents(self) -> list[Agent]:
        return sorted(self._agents.values(), key=lambda a: a.agent_id)

    async def set_status(self, agent_id: str, status: AgentStatus, drift: float | None = None) -> Agent:
        agent = self.agent(agent_id)
        agent.status = status
        if drift is not None:
            agent.drift = drift
        await self.store.set_agent_status(agent_id, status, agent.drift)
        return agent

    # ------------------------------------------------------------ tokens

    def issue_token(self, agent_id: str) -> IssuedToken:
        """A fresh root token scoped to the agent's current Role Contract."""
        agent = self.agent(agent_id)
        if agent.status is AgentStatus.quarantined:
            raise AgentQuarantined(agent_id)
        contract = self.contract(agent.role)
        return self._mint(
            agent_id=agent_id,
            contract=contract,
            scopes=list(contract.allowed_tools),
            chain=[agent_id],
            root_role=contract.role,
            ttl_s=self.settings.agent_token_ttl_s,
            act=None,
        )

    def verify(self, token: str) -> AgentToken:
        """Signature, expiry, audience, revocation, and that the agent still exists."""
        claims = verify_token(token, AUD_GATEWAY, self.settings)
        if self._is_revoked(claims["jti"]):
            raise TokenRevoked(claims["jti"])
        self.agent(claims["sub"])
        return AgentToken(
            agent_id=claims["sub"],
            role=claims["role"],
            role_version=claims["role_version"],
            scopes=claims["scopes"],
            chain=claims["chain"],
            depth=claims["depth"],
            root_role=claims["root_role"],
            jti=claims["jti"],
            expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
            act=claims.get("act"),
        )

    def refresh(self, token: str) -> IssuedToken:
        """Swap a still-valid root token for a new one. Delegated tokens can't be refreshed."""
        current = self.verify(token)
        if current.depth > 0:
            raise DelegationDenied("delegated tokens cannot be refreshed; ask the caller to delegate again")
        return self.issue_token(current.agent_id)

    async def revoke(self, jti: str, expires_at: datetime) -> None:
        self._revoked[jti] = expires_at
        await self.store.revoke(jti, expires_at)

    async def revoke_agent(self, agent_id: str) -> list[str]:
        """Revoke every live token held by the agent and every token delegated from it."""
        self._prune()
        doomed = [t for t in self._live.values() if agent_id in t.chain]
        for t in doomed:
            await self.revoke(t.jti, t.expires_at)
        return [t.jti for t in doomed]

    # ------------------------------------------------------------ delegation

    def delegate(self, caller: AgentToken, callee_id: str) -> IssuedToken:
        """Issue an attenuated token for `callee_id` acting on behalf of `caller`.

        Effective scopes = caller scopes ∩ callee's role tools, so authority can
        only shrink along a chain.
        """
        callee = self.agent(callee_id)
        if callee.status is AgentStatus.quarantined:
            raise AgentQuarantined(callee_id)
        caller_contract = self.contract(caller.role)
        if callee_id not in caller_contract.delegation.may_call:
            raise DelegationDenied(f"{caller.agent_id} ({caller.role}) may not call {callee_id}")
        if callee_id in caller.chain:
            raise DelegationDenied("delegation cycle")
        depth = caller.depth + 1
        if depth > caller_contract.delegation.max_depth:
            raise DelegationDenied(f"delegation depth {depth} exceeds {caller_contract.delegation.max_depth}")

        callee_contract = self.contract(callee.role)
        scopes = [s for s in callee_contract.allowed_tools if s in caller.scopes]
        remaining = int((caller.expires_at - utcnow()).total_seconds())
        if remaining <= 0:
            raise DelegationDenied("caller token has expired")
        actor: dict[str, Any] = {"sub": caller.agent_id}
        if caller.act:
            actor["act"] = caller.act
        return self._mint(
            agent_id=callee_id,
            contract=callee_contract,
            scopes=scopes,
            chain=[*caller.chain, callee_id],
            root_role=caller.root_role,
            ttl_s=min(remaining, self.settings.agent_token_ttl_s),
            act=actor,
        )

    # ------------------------------------------------------------ internals

    def _mint(
        self,
        *,
        agent_id: str,
        contract: RoleContract,
        scopes: list[str],
        chain: list[str],
        root_role: str,
        ttl_s: int,
        act: dict[str, Any] | None,
    ) -> IssuedToken:
        claims: dict[str, Any] = {
            "role": contract.role,
            "role_version": contract.version,
            "scopes": scopes,
            "chain": chain,
            "depth": len(chain) - 1,
            "root_role": root_role,
        }
        if act:
            claims["act"] = act
        token, payload = issue_token(agent_id, AUD_GATEWAY, ttl_s, claims, self.settings)
        parsed = AgentToken(
            agent_id=agent_id,
            jti=payload["jti"],
            expires_at=payload["exp"],
            act=act,
            **{k: v for k, v in claims.items() if k != "act"},
        )
        self._prune()
        self._live[parsed.jti] = parsed
        return IssuedToken(token=token, claims=parsed)

    def _is_revoked(self, jti: str) -> bool:
        exp = self._revoked.get(jti)
        return exp is not None and exp > utcnow()

    def _prune(self) -> None:
        now = utcnow()
        self._live = {j: t for j, t in self._live.items() if t.expires_at > now}
        self._revoked = {j: e for j, e in self._revoked.items() if e > now}

    def _put_version(self, v: _Version) -> None:
        self._versions.setdefault(v.contract.role, {})[v.contract.version] = v

    async def _save_version(self, v: _Version) -> None:
        body = v.contract.model_dump(mode="json")
        await self.store.save_contract_version(
            {
                "role": v.contract.role,
                "version": v.contract.version,
                "contract": body,
                "signature": sign(body, self.settings.jwt_signing_key),
                "amendment_id": v.amendment_id,
                "expires_at": v.expires_at,
            }
        )
        self._put_version(v)


def _amendment_body(a: RoleAmendment) -> dict[str, Any]:
    return a.model_dump(mode="json", exclude={"signature"})
