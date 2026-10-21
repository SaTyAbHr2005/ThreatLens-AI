import pytest

from threatlens.core.config import get_settings
from threatlens.core.schemas import Sensitivity, TrustLevel
from threatlens.gateway import BadToolArgs, Catalog, UnknownTool, in_scope


@pytest.fixture(scope="module")
def cat() -> Catalog:
    return Catalog.load(get_settings().catalog_dir)


def test_every_contract_tool_is_in_the_catalog(cat):
    from threatlens.identity import load_role_dir

    for contract in load_role_dir(get_settings().roles_dir):
        missing = set(contract.allowed_tools) - set(cat.tools)
        assert not missing, f"{contract.role}: {missing}"


@pytest.mark.parametrize(
    "path, sensitivity, cls",
    [
        ("/hr/salaries.xlsx", Sensitivity.restricted, "hr.compensation"),
        ("/hr/policies/leave.md", Sensitivity.internal, "hr.policy"),
        ("/hr/reviews/2026.docx", Sensitivity.confidential, "hr.records"),
        ("/procurement/policy.md", Sensitivity.internal, "procurement.docs"),
        ("/shared/templates/po.docx", Sensitivity.public, "shared.templates"),
    ],
)
def test_file_labels(cat, path, sensitivity, cls):
    a = cat.resolve("files.read", {"path": path})
    assert (a.label.sensitivity, a.label.resource_class) == (sensitivity, cls)


@pytest.mark.parametrize("sneaky", ["/procurement/../hr/salaries.xlsx", "//hr/salaries.xlsx", "/procurement/./../hr/salaries.xlsx"])
def test_path_tricks_cannot_dodge_labels_or_scopes(cat, sneaky):
    a = cat.resolve("files.read", {"path": sneaky})
    assert a.resource == "/hr/salaries.xlsx"
    assert a.label.sensitivity is Sensitivity.restricted
    assert not in_scope("path", a.resource, ["/procurement/**"])


def test_inbox_files_are_untrusted_content(cat):
    a = cat.resolve("files.read", {"path": "/inbox/procurement/supplier_quote.pdf"})
    assert a.label.trust is TrustLevel.untrusted and a.untrusted_output
    assert not cat.resolve("files.read", {"path": "/procurement/policy.md"}).untrusted_output


def test_canary_is_flagged(cat):
    assert cat.resolve("files.read", {"path": "/hr/salaries_2026_FINAL.xlsx"}).label.canary
    assert not cat.resolve("files.read", {"path": "/hr/salaries.xlsx"}).label.canary


def test_egress_destination_and_bytes(cat):
    a = cat.resolve("http.post", {"url": "https://Quote-Verify.io/upload?x=1", "body": "data"})
    assert a.destination == "quote-verify.io" and a.external and a.bytes_out > 0
    internal = cat.resolve("email.send", {"to": "lead@corp.example", "body": "hi"})
    assert not internal.external and internal.destination is None
    external = cat.resolve("email.send", {"to": "x@evil.example", "body": "hi"})
    assert external.external and external.destination == "evil.example"
    # Reads aren't egress.
    assert cat.resolve("web.fetch", {"url": "https://api.supplier-portal.example/c"}).bytes_out == 0


def test_templates_and_scopes(cat):
    a = cat.resolve("erp.read_invoice", {"invoice_id": "INV-2041"})
    assert a.resource == "invoices.INV-2041" and a.label.resource_class == "finance.invoices"
    assert in_scope("name", a.resource, ["invoices.*"])
    assert in_scope("email", "lead@corp.example", {"recipients": ["*@corp.example"]})
    assert not in_scope("email", "x@evil.example", {"recipients": ["*@corp.example"]})
    assert in_scope("url", "https://api.supplier-portal.example/x", ["api.supplier-portal.example"])


@pytest.mark.parametrize(
    "tool, args",
    [
        ("files.read", {"path": "relative/file.txt"}),
        ("files.read", {"path": "/procurement/*"}),
        ("files.read", {}),
        ("tickets.read", {"ticket_id": "*"}),
        ("erp.read_invoice", {}),
        ("http.post", {"url": "ftp://x.example/file"}),
        ("email.send", {"to": "a@b@c.example"}),
    ],
)
def test_bad_arguments_rejected(cat, tool, args):
    with pytest.raises(BadToolArgs):
        cat.resolve(tool, args)


def test_unknown_tool(cat):
    with pytest.raises(UnknownTool):
        cat.resolve("shell.exec", {"cmd": "rm -rf /"})
