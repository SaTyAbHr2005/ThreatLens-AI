"""Tool catalog + sensitivity labels: turn a raw tool call into a described action.

The labels are the SensitivityLabeler adapter: YAML here, the company's DLP /
data catalog in production (PRODUCTION.md §2).
"""

import hashlib
import json
import posixpath
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel

from threatlens.core.schemas import Action, Carrier, Sensitivity, TrustLevel


class UnknownTool(Exception):
    pass


class BadToolArgs(ValueError):
    pass


class ToolSpec(BaseModel):
    name: str
    kind: Literal["path", "url", "name", "email"] = "name"
    resource: str | None = None
    resource_arg: str | None = None
    resource_template: str | None = None
    egress: bool = False
    output: Literal["trusted", "untrusted", "by_label"] = "trusted"
    carrier: Carrier = "tool_output"
    phrase: str = ""  # plain-language description (M4 compares it with the role's purpose)


class Label(BaseModel):
    sensitivity: Sensitivity = Sensitivity.internal
    resource_class: str = "unclassified"
    trust: TrustLevel = TrustLevel.internal
    canary: bool = False


class _Rule(BaseModel):
    match: str
    label: Label


@dataclass(frozen=True)
class ResolvedAction:
    spec: ToolSpec
    resource: str
    label: Label
    destination: str | None  # host (url) or recipient domain (email)
    external: bool  # destination is outside the company
    bytes_out: int  # data sent to the destination (egress tools only)
    untrusted_output: bool

    @property
    def tool(self) -> str:
        return self.spec.name

    def to_action(self, args: dict[str, Any]) -> Action:
        return Action(
            tool=self.spec.name,
            resource=self.resource,
            resource_class=self.label.resource_class,
            sensitivity=self.label.sensitivity,
            args_digest="sha256:" + hashlib.sha256(_canonical(args)).hexdigest(),
            bytes_out=self.bytes_out,
            destination=self.destination,
        )


def in_scope(kind: str, resource: str, scope: Any) -> bool:
    """Does `resource` fall inside a contract/grant scope (list of globs or {recipients: [...]})?"""
    if isinstance(scope, dict):
        scope = scope.get("recipients", [])
    if not isinstance(scope, list):
        return False
    target = resource
    if kind == "url":
        target = (urlsplit(resource).hostname or "").lower()
    elif kind == "email":
        target = resource.lower()
    return any(g == "**" or fnmatchcase(target, g) for g in scope)


class Catalog:
    def __init__(self, tools: dict[str, ToolSpec], rules: list[_Rule], default: Label, internal_domains: list[str]):
        self.tools = tools
        self.rules = rules
        self.default = default
        self.internal_domains = [d.lower() for d in internal_domains]

    @classmethod
    def load(cls, directory: Path) -> "Catalog":
        tools_doc = yaml.safe_load((directory / "tools.yaml").read_text(encoding="utf-8"))
        labels_doc = yaml.safe_load((directory / "labels.yaml").read_text(encoding="utf-8"))
        tools = {name: ToolSpec(name=name, **spec) for name, spec in tools_doc.items()}

        def label(d: dict[str, Any]) -> Label:
            return Label(
                sensitivity=d.get("sensitivity", "internal"),
                resource_class=d.get("class", "unclassified"),
                trust=d.get("trust", "internal"),
                canary=d.get("canary", False),
            )

        rules = [_Rule(match=r["match"], label=label(r)) for r in labels_doc.get("rules", [])]
        return cls(tools, rules, label(labels_doc.get("default", {})), labels_doc.get("internal_domains", []))

    def is_internal(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d or domain.endswith("." + d) for d in self.internal_domains)

    def label(self, kind: str, resource: str) -> Label:
        if kind == "url":
            host = (urlsplit(resource).hostname or "").lower()
            if self.is_internal(host):
                return Label(sensitivity=Sensitivity.internal, resource_class="internal.web")
            return Label(sensitivity=Sensitivity.public, resource_class="external.web", trust=TrustLevel.untrusted)
        if kind == "email":
            internal = self.is_internal(resource.rpartition("@")[2])
            return Label(resource_class="email.internal" if internal else "email.external")
        for rule in self.rules:
            if fnmatchcase(resource, rule.match):
                return rule.label
        return self.default

    def resolve(self, tool: str, args: dict[str, Any]) -> ResolvedAction:
        spec = self.tools.get(tool)
        if spec is None:
            raise UnknownTool(tool)
        resource = self._resource(spec, args)
        label = self.label(spec.kind, resource)

        destination, external = None, False
        if spec.kind == "url":
            destination = (urlsplit(resource).hostname or "").lower()
            external = not self.is_internal(destination)
        elif spec.kind == "email":
            domain = resource.rpartition("@")[2].lower()
            external = not self.is_internal(domain)
            destination = domain if external else None

        untrusted = spec.output == "untrusted" or (spec.output == "by_label" and label.trust is TrustLevel.untrusted)
        return ResolvedAction(
            spec=spec,
            resource=resource,
            label=label,
            destination=destination,
            external=external,
            bytes_out=len(_canonical(args)) if spec.egress else 0,
            untrusted_output=untrusted,
        )

    @staticmethod
    def _resource(spec: ToolSpec, args: dict[str, Any]) -> str:
        if spec.resource:
            return spec.resource
        if spec.resource_template:
            try:
                value = spec.resource_template.format(**{k: str(v) for k, v in args.items()})
            except KeyError as e:
                raise BadToolArgs(f"{spec.name} needs argument {e}") from None
            return _no_wildcards(value)
        key = spec.resource_arg or "resource"
        value = args.get(key)
        if not isinstance(value, str) or not value.strip():
            raise BadToolArgs(f"{spec.name} needs a non-empty string argument '{key}'")
        value = value.strip()
        if spec.kind in ("path", "name"):
            value = _no_wildcards(value)
        if spec.kind == "path":
            # Normalize so "/procurement/../hr/x" or "//hr/x" can't dodge a scope or a label.
            if not value.startswith("/") or "\\" in value:
                raise BadToolArgs("paths must be absolute and use forward slashes")
            return "/" + posixpath.normpath(value).lstrip("/")
        if spec.kind == "url":
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise BadToolArgs("url must be http(s) with a host")
        if spec.kind == "email" and value.count("@") != 1:
            raise BadToolArgs("recipient must be one email address")
        return value


def _no_wildcards(value: str) -> str:
    # A tool could read "tickets.*" as "every ticket": names and paths must be literal.
    if any(c in value for c in "*?[]") or any(ord(c) < 32 for c in value):
        raise BadToolArgs("resource names can't contain wildcards or control characters")
    return value


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
