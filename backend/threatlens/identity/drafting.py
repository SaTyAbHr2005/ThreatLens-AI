"""AI-drafted Role Contracts. A draft is never saved: a person reviews it first."""

import re
from typing import Any

import yaml
from pydantic import ValidationError

from threatlens.core.llm import LLMRouter, LLMUnavailable
from threatlens.core.schemas import RoleContract

SYSTEM_PROMPT = """You write Role Contracts for AI agents as YAML. Least privilege: include only
tools and data the described job clearly needs. Use exactly these keys:
role (lowercase slug), version (1), purpose, owner (email), allowed_tools (list of
dotted tool names), resource_scopes (map of tool -> list of path/resource globs),
data_sensitivity_ceiling (public|internal|confidential|restricted), egress_allowlist
(list of hostnames, usually empty), prototype_actions (5-7 short examples of normal
work), delegation ({may_call: [], max_depth: 0}), enforcement_mode (shadow).
Return only the YAML."""

_FENCE = re.compile(r"```(?:ya?ml)?\s*(.*?)```", re.S)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:32] or "new-role"


def template_contract(description: str, owner: str) -> RoleContract:
    """Safe skeleton when no LLM is available: no tools until a person adds them."""
    return RoleContract(
        role=_slug(description.split(".")[0]),
        purpose=description.strip(),
        owner=owner,
        allowed_tools=[],
        prototype_actions=[],
        enforcement_mode="shadow",
    )


async def draft_contract(description: str, owner: str, llm: LLMRouter | None) -> dict[str, Any]:
    """Return {"contract", "yaml", "source", "note"}. New drafts start in shadow mode."""
    note = None
    if llm is not None:
        try:
            result = await llm.complete(
                "draft_contract",
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Owner: {owner}\nJob description: {description}"},
                ],
                temperature=0.1,
                max_tokens=900,
            )
            text = result.text or ""
            match = _FENCE.search(text)
            data = yaml.safe_load(match.group(1) if match else text)
            data.update(owner=owner, version=1, enforcement_mode="shadow")
            contract = RoleContract.model_validate(data)
            return {
                "contract": contract,
                "yaml": yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
                "source": f"llm:{result.provider}",
                "note": "Review every tool and scope before saving. New roles start in shadow mode.",
            }
        except LLMUnavailable as e:
            note = f"No LLM available ({e}); returned a template."
        except (yaml.YAMLError, ValidationError, AttributeError, TypeError) as e:
            note = f"The LLM draft was not a valid contract ({type(e).__name__}); returned a template."

    contract = template_contract(description, owner)
    return {
        "contract": contract,
        "yaml": yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
        "source": "template",
        "note": note or "No LLM configured; returned a template.",
    }
