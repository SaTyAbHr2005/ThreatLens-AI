import httpx

from threatlens.core.llm import LLMRouter, Provider
from threatlens.core.schemas import EnforcementMode
from threatlens.identity import draft_contract

DRAFT = """Here you go:
```yaml
role: invoice-reconciler
version: 7
purpose: Reconcile supplier invoices against the ledger.
owner: someone@else.example
allowed_tools: [erp.read_invoice, ledger.query]
resource_scopes: {erp.read_invoice: ["invoices.*"]}
data_sensitivity_ceiling: confidential
egress_allowlist: []
prototype_actions: ["match an invoice to its purchase order"]
delegation: {may_call: [], max_depth: 0}
enforcement_mode: enforce
```"""


def _router(text: str) -> LLMRouter:
    def handler(req):
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    return LLMRouter(
        [Provider("gemini", "gemini", "https://gemini.test/v1", "k", "m")],
        transport=httpx.MockTransport(handler),
    )


async def test_llm_draft_is_parsed_and_forced_safe():
    out = await draft_contract("An agent that reconciles invoices.", "fin@corp.example", _router(DRAFT))
    c = out["contract"]
    assert out["source"] == "llm:gemini"
    assert c.allowed_tools == ["erp.read_invoice", "ledger.query"]
    # The model can't choose these: owner comes from the request, drafts start at v1 in shadow mode.
    assert c.owner == "fin@corp.example" and c.version == 1
    assert c.enforcement_mode is EnforcementMode.shadow


async def test_invalid_llm_output_falls_back_to_template():
    out = await draft_contract("An agent that reconciles invoices.", "fin@corp.example", _router("no yaml here, sorry"))
    assert out["source"] == "template"
    assert out["contract"].allowed_tools == []


async def test_no_llm_gives_a_tool_less_template():
    out = await draft_contract("Triage security tickets. Escalate urgent ones.", "sec@corp.example", None)
    c = out["contract"]
    assert out["source"] == "template"
    assert c.role == "triage-security-tickets"
    assert c.allowed_tools == [] and c.enforcement_mode is EnforcementMode.shadow
