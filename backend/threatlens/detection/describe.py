"""Turn actions and Role Contracts into comparable plain-language phrases (for S1)."""

import re
from urllib.parse import urlsplit

from threatlens.core.schemas import RoleContract
from threatlens.gateway.catalog import Catalog, ResolvedAction

_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def words(s: str) -> str:
    return " ".join(w for w in _SPLIT.split(s.lower()) if w and not w.isdigit())


def _tool_phrase(catalog: Catalog, tool: str) -> str:
    spec = catalog.tools.get(tool)
    return spec.phrase if spec and spec.phrase else words(tool)


def describe(a: ResolvedAction) -> str:
    """e.g. 'read file hr salaries xlsx (hr compensation, restricted data)'."""
    phrase = a.spec.phrase or words(a.tool)
    if a.spec.kind == "url":
        host = (urlsplit(a.resource).hostname or "")
        where = f"external website {words(host)}" if a.external else f"internal site {words(host)}"
        return f"{phrase} {where}"
    if a.spec.kind == "email":
        who = f"external recipient at {words(a.destination or '')}" if a.external else "a colleague"
        return f"{phrase} to {who}"
    return f"{phrase} {words(a.resource)} ({words(a.label.resource_class)}, {a.label.sensitivity.value} data)"


def contract_phrases(contract: RoleContract, catalog: Catalog) -> list[str]:
    """What normal work for this role sounds like: purpose, prototypes, and each tool in each scope."""
    phrases = [contract.purpose.strip(), *contract.prototype_actions]
    for tool in contract.allowed_tools:
        phrase = _tool_phrase(catalog, tool)
        scope = contract.resource_scopes.get(tool)
        globs = scope.get("recipients", []) if isinstance(scope, dict) else (scope or [])
        if not globs:
            phrases.append(phrase)
        for g in globs:
            target = words(g.replace("*", " "))
            phrases.append(f"{phrase} {target}".strip())
    return list(dict.fromkeys(p for p in phrases if p))
