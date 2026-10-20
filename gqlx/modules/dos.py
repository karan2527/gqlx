"""
DoS Module  (requires --aggressive)
Tests for missing GraphQL resource-control limits.

Scope note: this module reports *capabilities* (the absence of a limit), not
confirmed outages — automated latency oracles are too noisy to prove resource
exhaustion safely. The deep-nesting latency check was removed because building a
genuinely deep query requires schema-cycle analysis; done naively (querying a
nonexistent `node` field) it produced false positives. What remains is measured
against real schema fields:

  * Alias flooding — many aliases of a real resolver accepted without a
    complexity error (tentative: limit is absent, impact not proven).
  * Batch abuse — the server processes an array of operations in one request
    (confirmed capability: the batch is demonstrably executed).
"""

from __future__ import annotations

import time

from gqlx.core.requester import RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, GraphQLSchema, RunContext

logger = get_logger(__name__)

_ALIAS_COUNT = 50
_BATCH_COUNT = 20
_SLOW_THRESHOLD_SECONDS = 5.0

_COMPLEXITY_KEYWORDS = [
    "complexity",
    "depth limit",
    "too deep",
    "query too complex",
    "max depth",
    "cost limit",
    "exceeds maximum",
    "too many",
    "rate limit",
    "throttl",
]


def _is_complexity_rejected(body: str) -> bool:
    body_lower = body.lower()
    return any(kw in body_lower for kw in _COMPLEXITY_KEYWORDS)


def _pick_alias_target(schema: GraphQLSchema) -> tuple[GraphQLField, str] | None:
    """Pick a real, no-argument query field and a valid selection for it.

    Aliasing a real resolver (not __typename, which costs nothing) is what makes
    the test meaningful. Prefers scalar-returning fields for a clean query.
    """
    no_arg = [f for f in schema.queries if not any(a.is_required for a in f.args)]
    # Prefer scalar leaves (no subselection needed).
    for f in no_arg:
        if schema.is_leaf_type(f.field_type):
            return f, ""
    for f in no_arg:
        sel = schema.build_selection(f)
        if sel:
            return f, sel
    return None


class DosModule(BaseModule):
    """Tests for missing GraphQL resource-control limits. Requires --aggressive."""

    metadata = ModuleMetadata(
        name="dos",
        description="Tests missing query-complexity and batch limits. Requires --aggressive.",
        requires_aggressive=True,
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://www.apollographql.com/blog/graphql-security-dos-attacks/",
            "https://graphql-armor.escape.tech/",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.aggressive or not ctx.schema:
            return []

        logger.warning(
            "dos_module_active",
            warning="Sending potentially resource-intensive queries to target",
        )

        findings: list[Finding] = []
        findings += await self._test_alias_flood(ctx)
        findings += await self._test_batch_abuse(ctx)
        return findings

    async def _test_alias_flood(self, ctx: RunContext) -> list[Finding]:
        assert ctx.schema is not None
        target = _pick_alias_target(ctx.schema)
        if target is None:
            logger.info("dos_no_alias_target")
            return []
        field, selection = target

        aliases = "\n".join(f"  a{i}: {field.name}{selection}" for i in range(_ALIAS_COUNT))
        query = f"{{\n{aliases}\n}}"

        start = time.monotonic()
        try:
            resp = await ctx.requester.graphql(query)
            elapsed = time.monotonic() - start
        except (RequestError, AttributeError):
            return []

        body = resp.text
        if _is_complexity_rejected(body):
            return []  # server enforces a limit — good
        # Confirm the aliases were actually executed (last alias present in data).
        if f'"a{_ALIAS_COUNT - 1}"' not in body and f"a{_ALIAS_COUNT - 1}" not in body:
            return []

        return [
            self.finding(
                title="No Query Complexity Limit — Alias Flooding Accepted",
                severity="medium",
                confidence="tentative",
                description=(
                    f"A query with {_ALIAS_COUNT} aliases of the real field "
                    f"'{field.name}' was executed without a complexity/cost error. The "
                    f"server lacks query-complexity limiting, so an attacker can multiply "
                    f"resolver work within a single request. Impact depends on the cost of "
                    f"the underlying resolver and is not proven here."
                ),
                endpoint=ctx.url,
                payload=truncate(query, 200),
                evidence=f"All {_ALIAS_COUNT} aliases resolved in {elapsed:.1f}s "
                + ("(slow)" if elapsed >= _SLOW_THRESHOLD_SECONDS else ""),
                remediation=(
                    "Enforce query complexity/cost analysis (e.g. graphql-query-complexity, "
                    "or graphql-armor's cost-limit plugin) that counts aliased fields."
                ),
            )
        ]

    async def _test_batch_abuse(self, ctx: RunContext) -> list[Finding]:
        batch: list[dict[str, str]] = [{"query": "{ __typename }"} for _ in range(_BATCH_COUNT)]
        start = time.monotonic()
        try:
            resp = await ctx.requester.graphql_batch(batch)
            elapsed = time.monotonic() - start
            parsed = resp.json()
        except Exception:
            return []

        if not isinstance(parsed, list) or len(parsed) < _BATCH_COUNT:
            return []  # batching disabled or coalesced

        return [
            self.finding(
                title="GraphQL Batching Enabled — No Batch-Size Limit",
                severity="medium",
                confidence="confirmed",
                description=(
                    f"The server accepted and executed a batch of {_BATCH_COUNT} operations "
                    f"in a single HTTP request, returning {len(parsed)} results. Without a "
                    f"batch-size limit, an attacker can multiply backend work per request "
                    f"and bypass per-request rate limiting (e.g. for credential stuffing)."
                ),
                endpoint=ctx.url,
                payload=f"Batch of {_BATCH_COUNT} operations",
                evidence=f"Received {len(parsed)} responses in {elapsed:.1f}s",
                remediation=(
                    "Limit batch size (recommended ≤10) or disable array batching "
                    "(Apollo Server: allowBatchedHttpRequests: false)."
                ),
            )
        ]
