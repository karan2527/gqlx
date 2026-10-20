"""
BOLA / IDOR Module
Detects Broken Object Level Authorization on ID-based fields.

Confirmation model:
  * With a single identity we cannot distinguish "anyone can read this object"
    from "this is the caller's own object" — so single-identity hits are
    reported as TENTATIVE leads (enumerable object IDs worth manual review).
  * With a second identity (--token-b) we perform a true cross-user
    differential: if user B receives the exact object data that user A saw for
    the same ID, object-level authorization is broken and the finding is
    CONFIRMED.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from gqlx.core.requester import Requester, RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

_PROBE_IDS = [
    "1",
    "2",
    "3",
    "0",
    "-1",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]

# An ID that should not correspond to any real object — used as a negative
# baseline so we only treat genuinely populated responses as "data".
_INVALID_ID = "99999999"

# Below this length ratio two bodies are considered meaningfully different.
_SIMILARITY_THRESHOLD = 0.95


def _normalized(text: str) -> str:
    return " ".join(text.split())


def _bodies_differ(a: str, b: str) -> bool:
    if not a or not b:
        return False
    ratio = min(len(a), len(b)) / max(len(a), len(b)) if max(len(a), len(b)) else 1.0
    if ratio < _SIMILARITY_THRESHOLD:
        return True
    return _normalized(a) != _normalized(b)


def _data_fingerprint(body: str) -> str | None:
    """Stable hash of the GraphQL `data` payload, ignoring key order and
    transport noise. Returns None if there is no non-empty data."""
    try:
        data = (json.loads(body) or {}).get("data")
    except (json.JSONDecodeError, AttributeError):
        return None
    if not data:
        return None
    if isinstance(data, dict) and not any(v not in (None, {}, []) for v in data.values()):
        return None
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _looks_like_data(body: str) -> bool:
    return _data_fingerprint(body) is not None


class BolaModule(BaseModule):
    """Probes ID-accepting fields for Broken Object Level Authorization."""

    metadata = ModuleMetadata(
        name="bola",
        description="Detects IDOR/BOLA in ID-based GraphQL fields via cross-identity comparison",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://salt.security/api-security-blog/what-is-bola",
            "https://portswigger.net/web-security/access-control/idor",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        targets = ctx.schema.id_fields()
        if not targets:
            logger.info("bola_no_id_fields")
            return []

        logger.info("bola_targets", count=len(targets), second_identity=ctx.has_second_identity)

        if ctx.has_second_identity:
            async with Requester(ctx.second_identity_config()) as req_b:
                tasks = [self._probe_field(ctx, field, req_b) for field in targets]
                nested = await asyncio.gather(*tasks)
        else:
            tasks = [self._probe_field(ctx, field, None) for field in targets]
            nested = await asyncio.gather(*tasks)

        return [f for batch in nested for f in batch]

    async def _probe_field(
        self, ctx: RunContext, field: GraphQLField, req_b: Requester | None
    ) -> list[Finding]:
        req_a = ctx.requester
        id_args = [a for a in field.args if a.type_name in {"ID", "ID!", "Int", "Int!"}]
        if not id_args:
            return []
        arg = id_args[0]
        selection = ctx.schema.build_selection(field) if ctx.schema else ""

        baseline = await self._fetch(req_a, ctx.url, field.name, arg.name, _INVALID_ID, selection)

        # IDs for which the primary identity (A) receives real object data.
        hits: list[tuple[str, str]] = []
        for probe_id in _PROBE_IDS:
            body = await self._fetch(req_a, ctx.url, field.name, arg.name, probe_id, selection)
            if body and _looks_like_data(body) and _bodies_differ(baseline or "", body):
                hits.append((probe_id, body))

        if not hits:
            return []

        if req_b is not None:
            return await self._confirm_cross_identity(ctx, field, arg.name, selection, hits, req_b)
        return self._tentative_finding(ctx, field, arg.name, hits)

    async def _confirm_cross_identity(
        self,
        ctx: RunContext,
        field: GraphQLField,
        arg_name: str,
        selection: str,
        hits: list[tuple[str, str]],
        req_b: Requester,
    ) -> list[Finding]:
        """A confirmed BOLA: identity B retrieves the same object data A saw."""
        for probe_id, a_body in hits:
            b_body = await self._fetch(req_b, ctx.url, field.name, arg_name, probe_id, selection)
            if not b_body:
                continue
            if _data_fingerprint(b_body) == _data_fingerprint(a_body):
                return [
                    self.finding(
                        title=f"BOLA / IDOR — {field.name}",
                        severity="high",
                        confidence="confirmed",
                        description=(
                            f"Two distinct authenticated identities received byte-identical "
                            f"object data from '{field.name}' for ID '{probe_id}'. Object-level "
                            f"authorization is not enforced: any user can read another user's "
                            f"object by supplying its ID. (If this object is intentionally "
                            f"public, treat as expected.)"
                        ),
                        endpoint=ctx.url,
                        payload=f'{field.name}({arg_name}: "{probe_id}")',
                        evidence=(
                            f"Identity A and identity B both returned the same data for ID "
                            f"{probe_id}: {truncate(a_body, 300)}"
                        ),
                        remediation=(
                            "Enforce object-level authorization in the resolver: verify the "
                            "requesting user owns or is explicitly granted access to the "
                            "requested object before returning it. Do not rely on unguessable "
                            "IDs alone."
                        ),
                    )
                ]
        return []

    def _tentative_finding(
        self, ctx: RunContext, field: GraphQLField, arg_name: str, hits: list[tuple[str, str]]
    ) -> list[Finding]:
        ids_str = ", ".join(h[0] for h in hits[:3])
        return [
            self.finding(
                title=f"Enumerable object IDs — {field.name} (possible BOLA)",
                severity="medium",
                confidence="tentative",
                description=(
                    f"The field '{field.name}' returned object data for multiple supplied "
                    f"IDs ({ids_str}). This may indicate missing object-level authorization, "
                    f"but with a single identity it cannot be distinguished from the caller "
                    f"legitimately accessing their own objects or public data. Re-run with "
                    f"--token-b (a second user's token) to confirm cross-user access."
                ),
                endpoint=ctx.url,
                payload=f"{field.name}({arg_name}: <ID>)",
                evidence=(
                    f"IDs {ids_str} each returned non-null data. Sample for ID {hits[0][0]}: "
                    f"{truncate(hits[0][1], 300)}"
                ),
                remediation=(
                    "Enforce object-level authorization on every resolver that accepts an ID. "
                    "Verify the requesting user owns or has explicit access to the resource."
                ),
            )
        ]

    async def _fetch(
        self, req: Requester, url: str, field: str, arg: str, value: str, selection: str
    ) -> str | None:
        query = f'{{ {field}({arg}: "{value}"){selection} }}'
        try:
            resp = await req.graphql(query, url=url)
            return resp.text
        except (RequestError, AttributeError):
            return None
