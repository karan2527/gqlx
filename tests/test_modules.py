"""Behavioural tests for the vulnerability modules.

These tests exercise each module's *confirmation logic* — the part that decides
whether a response is a real vulnerability, a tentative lead, or nothing — by
driving the modules with a scripted fake HTTP layer instead of a live target.

The fake requester routes every GraphQL call through a ``responder(query, config)``
callback so a test can return whatever body it likes (and branch on the calling
identity's ``Authorization`` header). This lets us prove the accuracy properties
the framework is built around:

  * heuristic-only hits are reported as ``tentative`` (SQLi/NoSQLi);
  * oracle-backed hits are ``confirmed`` (time-based CMDi, arithmetic SSTI,
    cross-identity BOLA/tenant, control-baseline SSRF);
  * differentials suppress false positives (SSTI reflection, SSRF control match,
    auth enforced).
"""

from __future__ import annotations

import asyncio
import json

from gqlx.core.requester import RequestError
from gqlx.utils.models import (
    GraphQLArgument,
    GraphQLField,
    GraphQLSchema,
    RunContext,
    ScanConfig,
    ScanResult,
)

URL = "https://target.example/graphql"


# --------------------------------------------------------------------------- #
# Fake HTTP harness
# --------------------------------------------------------------------------- #


class FakeResponse:
    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class FakeClock:
    """Deterministic monotonic clock that advances when a 'sleep 5' query runs."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def advance_for(self, query: str) -> None:
        self.now += 5.3 if "sleep 5" in query.lower() else 0.02


class CongestedClock:
    """Every request takes the same elevated time, regardless of payload.

    Models a NON-injectable field on a single-threaded server whose latency is
    inflated purely by concurrent load (another field's real sleep blocking the
    thread) — not by a shell our payload executed. The CMDi differential oracle
    must NOT confirm here, because the benign control is just as slow as the
    sleep payload.
    """

    def __init__(self, per_request: float = 5.3) -> None:
        self.now = 1000.0
        self.per_request = per_request

    def monotonic(self) -> float:
        return self.now

    def advance_for(self, query: str) -> None:
        self.now += self.per_request


class FakeRequester:
    """Implements the subset of Requester used by modules.

    ``responder(query, config) -> str | None`` decides the response body.
    Returning ``None`` simulates a transport failure (raises ``RequestError``),
    which is the signal modules treat as "no usable data".
    """

    def __init__(self, responder, config: ScanConfig | None = None, clock: FakeClock | None = None):
        self.responder = responder
        self.config = config
        self.clock = clock
        self.queries: list[str] = []

    async def __aenter__(self) -> FakeRequester:
        return self

    async def __aexit__(self, *_: object) -> bool:
        return False

    async def graphql(
        self, query, url=None, variables=None, operation_name=None, extra_headers=None
    ):
        self.queries.append(query)
        if self.clock is not None:
            self.clock.advance_for(query)
        text = self.responder(query, self.config)
        if text is None:
            raise RequestError("simulated transport failure")
        return FakeResponse(text)

    async def timed_graphql(self, query, url=None):
        """Mirror Requester.timed_graphql: return (response, round_trip_seconds).

        Elapsed is whatever the clock advances for this query, so a 'sleep 5'
        payload reads ~5.3s and a benign control reads ~0.02s. With no clock,
        elapsed is 0.0 (no timing-based finding can fire).
        """
        self.queries.append(query)
        before = self.clock.monotonic() if self.clock is not None else 0.0
        if self.clock is not None:
            self.clock.advance_for(query)
        after = self.clock.monotonic() if self.clock is not None else 0.0
        text = self.responder(query, self.config)
        if text is None:
            return None, 0.0
        return FakeResponse(text), after - before

    async def graphql_batch(self, operations, url=None):
        text = self.responder("__BATCH__:" + json.dumps(operations), self.config)
        if text is None:
            raise RequestError("simulated transport failure")
        return FakeResponse(text)

    def parse_json(self, resp):
        try:
            return resp.json()
        except Exception:
            return None


def patch_requester(monkeypatch, module_path: str, responder) -> None:
    """Replace a module's ``Requester`` symbol so identity-B / anon clients are faked."""
    monkeypatch.setattr(
        f"{module_path}.Requester",
        lambda cfg, *a, **k: FakeRequester(responder, cfg),
    )


def make_ctx(
    schema: GraphQLSchema,
    responder,
    *,
    headers: dict | None = None,
    headers_b: dict | None = None,
    aggressive: bool = False,
    introspection: bool = False,
    clock: FakeClock | None = None,
) -> RunContext:
    cfg = ScanConfig(
        url=URL,
        headers=headers or {},
        headers_b=headers_b or {},
        aggressive=aggressive,
    )
    result = ScanResult(target=URL)
    result.gql_schema = schema
    result.introspection_enabled = introspection
    return RunContext(config=cfg, result=result, requester=FakeRequester(responder, cfg, clock))


def run(coro):
    return asyncio.run(coro)


def field(
    name: str, *, ret: str = "String", args: list[GraphQLArgument] | None = None
) -> GraphQLField:
    return GraphQLField(name=name, field_type=ret, args=args or [])


def arg(name: str, type_name: str = "String!", required: bool = True) -> GraphQLArgument:
    return GraphQLArgument(name=name, type_name=type_name, is_required=required)


def schema_with(
    queries: list[GraphQLField], mutations: list[GraphQLField] | None = None
) -> GraphQLSchema:
    return GraphQLSchema(queries=queries, mutations=mutations or [], discovery_method="full")


# --------------------------------------------------------------------------- #
# Injection module
# --------------------------------------------------------------------------- #

from gqlx.modules.injection import InjectionModule  # noqa: E402


class TestInjection:
    def _schema(self) -> GraphQLSchema:
        return schema_with([field("search", args=[arg("query")])])

    def test_sqli_flagged_as_tentative(self) -> None:
        # A SQL error signature is heuristic evidence only → must be tentative.
        def responder(query, cfg):
            return '{"errors":[{"message":"You have an error in your SQL syntax near \\"\'\\""}]}'

        ctx = make_ctx(self._schema(), responder)
        findings = run(InjectionModule().run(ctx))

        sqli = [f for f in findings if f.title.startswith("SQL Injection")]
        assert sqli, "expected a SQLi lead from the error signature"
        assert all(f.confidence == "tentative" for f in sqli)
        # Nothing in this run is oracle-confirmed.
        assert all(f.confidence == "tentative" for f in findings)

    def test_clean_response_no_findings(self) -> None:
        ctx = make_ctx(self._schema(), lambda q, c: '{"data":{"search":[]}}')
        assert run(InjectionModule().run(ctx)) == []

    def test_cmdi_confirmed_by_timing(self) -> None:
        # Time-based oracle: a 'sleep 5' payload reproducibly delays the response.
        # Timing flows through the requester's timed_graphql (clean round-trip).
        clock = FakeClock()
        ctx = make_ctx(
            schema_with([field("run", args=[arg("cmd")])]),
            lambda q, c: '{"data":{"run":"ok"}}',
            clock=clock,
        )
        findings = run(InjectionModule().run(ctx))

        cmdi = [f for f in findings if f.title.startswith("Command Injection")]
        assert len(cmdi) == 1
        assert cmdi[0].confidence == "confirmed"
        assert cmdi[0].severity == "critical"

    def test_cmdi_not_confirmed_under_ambient_congestion(self) -> None:
        # Single-threaded-server false positive: every request is slow because of
        # concurrent load, not because our payload ran a shell. The control
        # differential must suppress this — no CMDi finding.
        clock = CongestedClock(per_request=5.3)
        ctx = make_ctx(
            schema_with([field("run", args=[arg("cmd")])]),
            lambda q, c: '{"data":{"run":"ok"}}',
            clock=clock,
        )
        findings = run(InjectionModule().run(ctx))
        assert not [f for f in findings if f.title.startswith("Command Injection")]

    def test_ssti_confirmed_by_arithmetic_differential(self) -> None:
        # Both probes must evaluate: 7*7→49 and 6*6→36.
        def responder(query, cfg):
            if "7*7" in query:
                return '{"data":{"search":"49"}}'
            if "6*6" in query:
                return '{"data":{"search":"36"}}'
            return '{"data":{"search":""}}'

        ctx = make_ctx(self._schema(), responder)
        findings = run(InjectionModule().run(ctx))
        ssti = [f for f in findings if f.title.startswith("Server-Side Template")]
        assert len(ssti) == 1
        assert ssti[0].confidence == "confirmed"

    def test_ssti_reflection_not_flagged(self) -> None:
        # The literal expression is echoed back unrendered → NOT a vulnerability.
        def responder(query, cfg):
            return '{"data":{"search":"{{7*7}} and {{6*6}} unrendered"}}'

        ctx = make_ctx(self._schema(), responder)
        findings = run(InjectionModule().run(ctx))
        assert not [f for f in findings if "Template" in f.title]


# --------------------------------------------------------------------------- #
# BOLA module
# --------------------------------------------------------------------------- #

from gqlx.modules.bola import BolaModule  # noqa: E402


class TestBola:
    def _schema(self) -> GraphQLSchema:
        return schema_with([field("user", ret="User", args=[arg("id", "ID!")])])

    def test_single_identity_is_tentative(self) -> None:
        def responder(query, cfg):
            if "99999999" in query:  # invalid-id baseline
                return '{"data":{"user":null}}'
            return '{"data":{"user":{"id":"1","email":"a@b.c"}}}'

        ctx = make_ctx(self._schema(), responder)
        findings = run(BolaModule().run(ctx))
        assert len(findings) == 1
        assert findings[0].confidence == "tentative"
        assert "Enumerable object IDs" in findings[0].title

    def test_cross_identity_confirmed(self, monkeypatch) -> None:
        # Identity B receives the exact object data A saw → BOLA confirmed.
        def responder(query, cfg):
            if "99999999" in query:
                return '{"data":{"user":null}}'
            return '{"data":{"user":{"id":"1","email":"a@b.c"}}}'

        patch_requester(monkeypatch, "gqlx.modules.bola", responder)
        ctx = make_ctx(
            self._schema(),
            responder,
            headers={"Authorization": "A"},
            headers_b={"Authorization": "B"},
        )
        findings = run(BolaModule().run(ctx))
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
        assert findings[0].severity == "high"

    def test_cross_identity_isolated_no_finding(self, monkeypatch) -> None:
        # Identity B cannot read A's object → authorization is working.
        def responder(query, cfg):
            if cfg and cfg.headers.get("Authorization") == "B":
                return '{"data":{"user":null}}'
            if "99999999" in query:
                return '{"data":{"user":null}}'
            return '{"data":{"user":{"id":"1"}}}'

        patch_requester(monkeypatch, "gqlx.modules.bola", responder)
        ctx = make_ctx(
            self._schema(),
            responder,
            headers={"Authorization": "A"},
            headers_b={"Authorization": "B"},
        )
        assert run(BolaModule().run(ctx)) == []


# --------------------------------------------------------------------------- #
# Auth module
# --------------------------------------------------------------------------- #

from gqlx.modules.auth import AuthModule  # noqa: E402


class TestAuth:
    def _schema(self) -> GraphQLSchema:
        return schema_with([field("me", ret="User")])

    def test_missing_auth_confirmed(self, monkeypatch) -> None:
        # Field returns data even with no Authorization header → missing auth.
        def responder(query, cfg):
            return '{"data":{"me":{"id":"1"}}}'

        patch_requester(monkeypatch, "gqlx.modules.auth", responder)
        ctx = make_ctx(self._schema(), responder, headers={"Authorization": "Bearer real"})
        findings = run(AuthModule().run(ctx))
        unauth = [f for f in findings if f.title.startswith("Unauthenticated Access")]
        assert len(unauth) == 1
        assert unauth[0].confidence == "confirmed"

    def test_auth_enforced_no_findings(self, monkeypatch) -> None:
        # Data only with the real token; missing/invalid tokens get nothing.
        def responder(query, cfg):
            if cfg and cfg.headers.get("Authorization") == "Bearer real":
                return '{"data":{"me":{"id":"1"}}}'
            return '{"data":{"me":null}}'

        patch_requester(monkeypatch, "gqlx.modules.auth", responder)
        ctx = make_ctx(self._schema(), responder, headers={"Authorization": "Bearer real"})
        assert run(AuthModule().run(ctx)) == []

    def test_invalid_token_accepted_confirmed(self, monkeypatch) -> None:
        # Auth required when absent, but ANY non-empty token is accepted → broken.
        def responder(query, cfg):
            token = cfg.headers.get("Authorization") if cfg else None
            return '{"data":{"me":{"id":"1"}}}' if token else '{"data":{"me":null}}'

        patch_requester(monkeypatch, "gqlx.modules.auth", responder)
        ctx = make_ctx(self._schema(), responder, headers={"Authorization": "Bearer real"})
        findings = run(AuthModule().run(ctx))
        invalid = [f for f in findings if f.title == "Invalid Bearer Token Accepted"]
        assert len(invalid) == 1
        assert invalid[0].confidence == "confirmed"
        # The gate works for the *absent* header, so this is not "unauthenticated".
        assert not [f for f in findings if f.title.startswith("Unauthenticated Access")]


# --------------------------------------------------------------------------- #
# Tenant isolation module
# --------------------------------------------------------------------------- #

from gqlx.modules.tenant_isolation import TenantIsolationModule  # noqa: E402


class TestTenantIsolation:
    def _schema(self, name: str) -> GraphQLSchema:
        return schema_with([field(name, ret="Result", args=[arg("organization_id", "ID!")])])

    def test_single_identity_is_tentative(self) -> None:
        def responder(query, cfg):
            if "nonexistent-org" in query:
                return '{"data":{"orgData":null}}'
            return '{"data":{"orgData":{"secret":"x"}}}'

        ctx = make_ctx(self._schema("orgData"), responder)
        findings = run(TenantIsolationModule().run(ctx))
        assert len(findings) == 1
        assert findings[0].confidence == "tentative"

    def test_cross_identity_confirmed_critical_for_sensitive(self, monkeypatch) -> None:
        # 'billing' is a sensitive field → confirmed cross-tenant read is critical.
        def responder(query, cfg):
            if "nonexistent-org" in query:
                return '{"data":{"billingData":null}}'
            return '{"data":{"billingData":{"amount":42}}}'

        patch_requester(monkeypatch, "gqlx.modules.tenant_isolation", responder)
        ctx = make_ctx(
            self._schema("billingData"),
            responder,
            headers={"Authorization": "A"},
            headers_b={"Authorization": "B"},
        )
        findings = run(TenantIsolationModule().run(ctx))
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
        assert findings[0].severity == "critical"

    def test_cross_identity_isolated_no_finding(self, monkeypatch) -> None:
        def responder(query, cfg):
            if cfg and cfg.headers.get("Authorization") == "B":
                return '{"data":{"orgData":null}}'
            if "nonexistent-org" in query:
                return '{"data":{"orgData":null}}'
            return '{"data":{"orgData":{"secret":"x"}}}'

        patch_requester(monkeypatch, "gqlx.modules.tenant_isolation", responder)
        ctx = make_ctx(
            self._schema("orgData"),
            responder,
            headers={"Authorization": "A"},
            headers_b={"Authorization": "B"},
        )
        assert run(TenantIsolationModule().run(ctx)) == []


# --------------------------------------------------------------------------- #
# SSRF module
# --------------------------------------------------------------------------- #

from gqlx.modules.ssrf import SsrfModule  # noqa: E402


class TestSsrf:
    def _schema(self) -> GraphQLSchema:
        return schema_with([field("fetchUrl", args=[arg("url")])])

    def test_metadata_hit_confirmed_against_control(self) -> None:
        def responder(query, cfg):
            if "gqlx-control.invalid" in query:
                return '{"data":{"fetchUrl":"connection refused"}}'
            if "169.254.169.254/latest" in query:
                return '{"data":{"fetchUrl":"AccessKeyId ASIA... security-credentials ami-id"}}'
            return '{"data":{"fetchUrl":""}}'

        ctx = make_ctx(self._schema(), responder)
        findings = run(SsrfModule().run(ctx))
        ssrf = [f for f in findings if f.title.startswith("SSRF")]
        assert ssrf
        assert ssrf[0].confidence == "confirmed"
        assert ssrf[0].severity == "critical"

    def test_no_finding_when_control_also_matches(self) -> None:
        # The signature appears for the benign control too → not a real SSRF.
        def responder(query, cfg):
            return '{"data":{"fetchUrl":"AccessKeyId security-credentials"}}'

        ctx = make_ctx(self._schema(), responder)
        assert run(SsrfModule().run(ctx)) == []


# --------------------------------------------------------------------------- #
# DoS module
# --------------------------------------------------------------------------- #

from gqlx.modules.dos import DosModule  # noqa: E402


class TestDos:
    def _schema(self) -> GraphQLSchema:
        return schema_with([field("ping", ret="String")])

    def test_requires_aggressive_flag(self) -> None:
        ctx = make_ctx(self._schema(), lambda q, c: "{}", aggressive=False)
        assert run(DosModule().run(ctx)) == []

    def test_alias_flood_tentative_and_batch_confirmed(self) -> None:
        def responder(query, cfg):
            if query.startswith("__BATCH__"):
                return json.dumps([{"data": {"__typename": "Query"}}] * 20)
            return '{"data":{"a49":"pong"}}'  # last alias present, no complexity error

        ctx = make_ctx(self._schema(), responder, aggressive=True)
        findings = run(DosModule().run(ctx))
        alias = [f for f in findings if "Alias Flooding" in f.title]
        batch = [f for f in findings if "Batching" in f.title]
        assert len(alias) == 1 and alias[0].confidence == "tentative"
        assert len(batch) == 1 and batch[0].confidence == "confirmed"

    def test_alias_flood_suppressed_when_complexity_rejected(self) -> None:
        def responder(query, cfg):
            if query.startswith("__BATCH__"):
                return json.dumps([{"errors": []}])  # batching coalesced / off
            return '{"errors":[{"message":"query is too complex (cost limit exceeded)"}]}'

        ctx = make_ctx(self._schema(), responder, aggressive=True)
        findings = run(DosModule().run(ctx))
        assert not [f for f in findings if "Alias Flooding" in f.title]


# --------------------------------------------------------------------------- #
# Info disclosure module
# --------------------------------------------------------------------------- #

from gqlx.modules.info_disclosure import InfoDisclosureModule  # noqa: E402


class TestInfoDisclosure:
    def test_introspection_enabled_finding(self) -> None:
        ctx = make_ctx(
            schema_with([field("me", ret="User")]),
            lambda q, c: '{"data":{}}',
            introspection=True,
        )
        findings = run(InfoDisclosureModule().run(ctx))
        intro = [f for f in findings if f.title == "GraphQL Introspection Enabled"]
        assert len(intro) == 1
        assert intro[0].severity == "medium"

    def test_stack_trace_leak_high(self) -> None:
        ctx = make_ctx(
            schema_with([field("me", ret="User")]),
            lambda q, c: 'Traceback (most recent call last): File "/app/x.py"',
            introspection=False,
        )
        findings = run(InfoDisclosureModule().run(ctx))
        stack = [f for f in findings if "Stack Trace" in f.title]
        assert len(stack) == 1
        assert stack[0].severity == "high"


# --------------------------------------------------------------------------- #
# Scorer — confidence discount
# --------------------------------------------------------------------------- #

from gqlx.core.scorer import score  # noqa: E402
from gqlx.utils.models import Finding  # noqa: E402


class TestConfidenceScoring:
    def _finding(self, confidence: str) -> Finding:
        return Finding(
            title="t",
            severity="high",
            confidence=confidence,  # type: ignore[arg-type]
            description="",
            endpoint=URL,
            module="injection",
            evidence="",
            remediation="",
        )

    def test_tentative_scored_below_confirmed(self) -> None:
        assert score(self._finding("tentative")) < score(self._finding("confirmed"))
