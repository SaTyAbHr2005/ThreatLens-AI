"""Role Contract files, amendment changes, and tamper-evident signatures."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from threatlens.core.schemas import RoleContract

from .errors import InvalidAmendment

# Fields an amendment may never change.
_FROZEN = {"role", "version"}


def load_contract_file(path: Path) -> RoleContract:
    return RoleContract.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_role_dir(directory: Path) -> list[RoleContract]:
    return [load_contract_file(p) for p in sorted(directory.glob("*.yaml"))]


def apply_changes(contract: RoleContract, changes: dict[str, Any]) -> RoleContract:
    """Return the next contract version with `changes` applied.

    - list fields: `{"add": [...], "remove": [...]}` edits in place; a plain list replaces
    - `resource_scopes`: merged key by key (`null` removes a tool's scope)
    - everything else: replaced
    """
    if not changes:
        raise InvalidAmendment("an amendment must change something")
    data = contract.model_dump(mode="json")
    for key, value in changes.items():
        if key in _FROZEN or key not in data:
            raise InvalidAmendment(f"field {key!r} cannot be amended")
        current = data[key]
        if isinstance(current, list) and isinstance(value, dict):
            unknown = set(value) - {"add", "remove"}
            if unknown:
                raise InvalidAmendment(f"list edits support only add/remove, got {sorted(unknown)}")
            remove = set(value.get("remove", []))
            kept = [v for v in current if v not in remove]
            data[key] = kept + [v for v in value.get("add", []) if v not in kept]
        elif key == "resource_scopes" and isinstance(value, dict):
            merged = {**current, **value}
            data[key] = {k: v for k, v in merged.items() if v is not None}
        else:
            data[key] = value
    data["version"] = contract.version + 1
    try:
        return RoleContract.model_validate(data)
    except ValidationError as e:
        raise InvalidAmendment(str(e)) from e


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def sign(obj: Any, key: str) -> str:
    return hmac.new(key.encode(), canonical(obj), hashlib.sha256).hexdigest()


def verify_signature(obj: Any, signature: str | None, key: str) -> bool:
    return signature is not None and hmac.compare_digest(sign(obj, key), signature)
