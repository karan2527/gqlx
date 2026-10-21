"""
Tenant Isolation Module
Tests whether organization_id-scoped queries enforce tenant boundaries.

Confirmation model mirrors BOLA: a single identity can only flag that a foreign
organization_id returned data (TENTATIVE — the guessed org may not be a real
other tenant, or the data may be the caller's own). With a second identity
(--token-b) we confirm cross-tenant access: if user B retrieves the same org's
data that user A saw for a given organization_id, isolation is broken.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from gqlx.core.requester import Requester, RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, RunContext, SeverityLevel

logger = get_logger(__name__)

# Probe org IDs — sequential, UUIDs, and common test values.
_PROBE_ORG_IDS = [
    "1",
    "2",
    "3",
    "100",
    "admin",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "ORG001",
    "ORG002",
    "org-1",
    "org-2",
    "test",
    "default",
    "root",
]

# An org id unlikely to exist, used as the negative baseline.
_INVALID_ORG_ID = "gqlx-nonexistent-org-000"

_SENSITIVE_FIELD_HINTS = {
    "user",
    "audit",
    "billing",
    "payment",
    "invoice",
    "transaction",
    "log",
    "report",
    "ai",
    "api",
    "key",
    "secret",
    "setting",
    "config",
    "role",
    "permission",
}


def _data_fp(body: str, field_name: str) -> str | None:
    """Hash of the field's non-empty data, or None."""
    try:
        data = (json.loads(body) or {}).get("data")
    except (json.JSONDecodeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    val = data.get(field_name)
    if val is None or val == {} or val == []:
        return None
    return hashlib.sha256(
        json.dumps(val, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_sensitive_field(name: str) -> bool:
    name_lower = name.lower()
    return any(hint in name_lower for hint in _SENSITIVE_FIELD_HINTS)


class TenantIsolationModule(BaseModule):
    """Tests multi-tenant isolation on organization_id-scoped operations."""

    metadata = ModuleMetadata(
        name="tenant_isolation",
        description="Tests cross-tenant data access via organization_id (confirmed with --token-b)",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://portswigger.net/web-security/access-control/idor",
            "https://salt.security/api-security-blog/what-is-bola",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        org_scoped = self._find_org_scoped_fields(ctx.schema.all_operations())
        if not org_scoped:
            logger.info("tenant_isolation_no_org_scoped_fields")
            return []

        logger.info(
            "tenant_isolation_targets",
            count=len(org_scoped),
            second_identity=ctx.has_second_identity,
        )

        if ctx.has_second_identity:
            async with Requester(ctx.second_identity_config()) as req_b:
                nested = await asyncio.gather(
                    *(self._test_field(ctx, f, req_b) for f in org_scoped)
                )
        else:
            nested = await asyncio.gather(*(self._test_field(ctx, f, None) for f in org_scoped))
        return [f for batch in nested for f in batch]

    def _find_org_scoped_fields(self, fields: list[GraphQLField]) -> list[GraphQLField]:
        result = []
        for f in fields:
            for arg in f.args:
                if "organization_id" in arg.name.lower() or "org_id" in arg.name.lower():
                    result.append(f)
                    break
        return result

    async def _test_field(
        self, ctx: RunContext, field: GraphQLField, req_b: Requester | None
    ) -> list[Finding]:
        req_a = ctx.requester
        selection = ctx.schema.build_selection(field) if ctx.schema else ""

        baseline_fp = _data_fp(
            await self._query(req_a, ctx.url, field, _INVALID_ORG_ID, selection) or "",
            field.name,
        )

        # org ids for which identity A receives real, distinct data
        hits: list[tuple[str, str, str]] = []  # (org_id, body, data_fp)
        for probe_id in _PROBE_ORG_IDS:
            body = await self._query(req_a, ctx.url, field, probe_id, selection)
            if not body:
                continue
            fp = _data_fp(body, field.name)
            if fp and fp != baseline_fp:
                hits.append((probe_id, body, fp))

        if not hits:
            return []

        if req_b is not None:
            return await self._confirm(ctx, field, selection, hits, req_b)
        return self._tentative(ctx, field, hits)

    async def _confirm(
        self,
        ctx: RunContext,
        field: GraphQLField,
        selection: str,
        hits: list[tuple[str, str, str]],
        req_b: Requester,
    ) -> list[Finding]:
        for probe_id, a_body, a_fp in hits:
            b_body = await self._query(req_b, ctx.url, field, probe_id, selection)
            if b_body and _data_fp(b_body, field.name) == a_fp:
                severity: SeverityLevel = "critical" if _is_sensitive_field(field.name) else "high"
                return [
                    self.finding(
                        title=f"Tenant Isolation Failure — {field.name}",
                        severity=severity,
                        confidence="confirmed",
                        description=(
                            f"Two distinct authenticated identities received identical data "
                            f"from '{field.name}' for organization_id='{probe_id}'. The "
                            f"resolver trusts the client-supplied organization_id instead of "
                            f"the authenticated user's org claim, so any user can read any "
                            f"organization's data — a critical multi-tenant BOLA."
                        ),
                        endpoint=ctx.url,
                        payload=f'{field.name}(organization_id: "{probe_id}")',
                        evidence=(
                            f"Identity A and identity B both returned the same data for "
                            f"organization_id={probe_id}: {truncate(a_body, 400)}"
                        ),
                        remediation=(
                            "Derive the tenant from the verified JWT claim "
                            "($ctx.identity.claims in AppSync), never from a client-supplied "
                            "organization_id. Reject requests whose org argument does not "
                            "match the caller's claim."
                        ),
                    )
                ]
        return []

    def _tentative(
        self, ctx: RunContext, field: GraphQLField, hits: list[tuple[str, str, str]]
    ) -> list[Finding]:
        ids_str = ", ".join(h[0] for h in hits[:3])
        severity: SeverityLevel = "high" if _is_sensitive_field(field.name) else "medium"
        return [
            self.finding(
                title=f"Possible Tenant Isolation Weakness — {field.name}",
                severity=severity,
                confidence="tentative",
                description=(
                    f"The field '{field.name}' returned distinct data for foreign "
                    f"organization_id values ({ids_str}). This may indicate the resolver "
                    f"trusts client-supplied org IDs, but with a single identity it cannot "
                    f"be distinguished from the caller's own data or non-existent orgs. "
                    f"Re-run with --token-b (a second tenant's token) to confirm."
                ),
                endpoint=ctx.url,
                payload=f'{field.name}(organization_id: "{ids_str}")',
                evidence=truncate(hits[0][1], 400),
                remediation=(
                    "Derive the tenant from the verified JWT claim, never from a "
                    "client-supplied organization_id."
                ),
            )
        ]

    async def _query(
        self, req: Requester, url: str, field: GraphQLField, org_id: str, selection: str
    ) -> str | None:
        args_parts = [f'organization_id: "{org_id}"']
        for arg in field.args:
            if "organization_id" in arg.name.lower() or "org_id" in arg.name.lower():
                continue
            if not arg.is_required:
                continue
            base = arg.type_name.rstrip("!")
            if base in ("Int", "Float"):
                args_parts.append(f"{arg.name}: 10")
            elif base == "Boolean":
                args_parts.append(f"{arg.name}: true")
            elif base in ("String", "ID", "AWSJSON", "AWSEmail"):
                args_parts.append(f'{arg.name}: "test"')

        query = f"{{ {field.name}({', '.join(args_parts)}){selection} }}"
        try:
            resp = await req.graphql(query, url=url)
            return resp.text
        except (RequestError, AttributeError):
            return None
