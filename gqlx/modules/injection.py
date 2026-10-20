"""
Injection Module
Tests GraphQL string arguments for SQLi, NoSQLi, command injection,
and server-side template injection (SSTI).
"""

from __future__ import annotations

import asyncio

from gqlx.core.requester import Requester, RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import load_payload_file, truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

# Template-engine wrappers. We confirm SSTI by arithmetic differential — the
# expression must evaluate for TWO distinct operand pairs (7*7=49 AND 6*6=36),
# which a stray "49" in a normal response cannot satisfy.
_SSTI_WRAPPERS = [("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%= ", " %>")]
_SSTI_PAIRS = [(7, 7, "49"), (6, 6, "36")]

# Time-based command injection. We confirm by measuring the induced delay
# rather than matching error strings, which removes the false positives that
# come from echoing the payload back in a GraphQL error.
_CMDI_SLEEP_SECONDS = 5
_CMDI_SLEEP_PAYLOADS = [
    f"; sleep {_CMDI_SLEEP_SECONDS} #",
    f"| sleep {_CMDI_SLEEP_SECONDS}",
    f"$(sleep {_CMDI_SLEEP_SECONDS})",
    f"`sleep {_CMDI_SLEEP_SECONDS}`",
]


class InjectionModule(BaseModule):
    """Tests injectable string arguments for common server-side injection vulnerabilities."""

    metadata = ModuleMetadata(
        name="injection",
        description="SQLi, NoSQLi, command injection, and SSTI via GraphQL string arguments",
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://graphql.org/learn/queries/#arguments",
            "https://portswigger.net/web-security/graphql",
        ],
    )

    def __init__(self) -> None:
        self._sqli = load_payload_file("sqli.json")
        self._nosqli = load_payload_file("nosqli.json")
        # Serializes the time-based probes so two fields' sleep/control pairs
        # never overlap — a concurrent sleep would otherwise inflate another
        # field's control measurement and defeat the differential.
        self._cmdi_lock = asyncio.Lock()

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            logger.warning("injection_no_schema")
            return []

        targets = ctx.schema.injectable_fields()
        if not targets:
            logger.info("injection_no_injectable_fields")
            return []

        logger.info("injection_targets", count=len(targets))
        tasks = [self._test_field(ctx, field) for field in targets]
        nested = await asyncio.gather(*tasks)
        return [f for batch in nested for f in batch]

    async def _test_field(self, ctx: RunContext, field: GraphQLField) -> list[Finding]:
        findings: list[Finding] = []
        req = ctx.requester
        # A valid subselection is required for object-returning fields, otherwise
        # the query fails GraphQL validation before the resolver ever runs.
        selection = ctx.schema.build_selection(field) if ctx.schema else ""

        for arg in field.args:
            if arg.type_name not in {"String", "String!", "ID", "ID!"}:
                continue

            findings += await self._test_sqli(ctx, req, field, arg.name, selection)
            findings += await self._test_nosqli(ctx, req, field, arg.name, selection)
            findings += await self._test_cmdi(ctx, req, field, arg.name, selection)
            findings += await self._test_ssti(ctx, req, field, arg.name, selection)

        return findings

    # ------------------------------------------------------------------ #
    # SQLi
    # ------------------------------------------------------------------ #

    async def _test_sqli(
        self, ctx: RunContext, req: Requester, field: GraphQLField, arg: str, selection: str
    ) -> list[Finding]:
        payloads: list[str] = self._sqli.get("payloads", [])
        signatures: list[str] = self._sqli.get("error_signatures", [])

        for payload in payloads:
            query = self._build_query(field.name, arg, payload, selection)
            try:
                resp = await req.graphql(query)
                body = resp.text
                matched = next((s for s in signatures if s.lower() in body.lower()), None)
                if matched:
                    return [
                        self.finding(
                            title=f"SQL Injection — {field.name}.{arg}",
                            severity="critical",
                            confidence="tentative",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' may be "
                                f"vulnerable to SQL injection. A database error signature "
                                f"was detected in the response, suggesting unsanitized "
                                f"input reaches a SQL query. This is error-based evidence "
                                f"only — confirm with a boolean/time-based differential "
                                f"before reporting as exploitable."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"Signature: '{matched}'. Response: {truncate(body, 400)}",
                            remediation=(
                                "Use parameterized queries or prepared statements. Never "
                                "concatenate user input directly into SQL strings. Use an ORM "
                                "that handles escaping automatically."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # NoSQLi
    # ------------------------------------------------------------------ #

    async def _test_nosqli(
        self, ctx: RunContext, req: Requester, field: GraphQLField, arg: str, selection: str
    ) -> list[Finding]:
        payloads: list[str] = self._nosqli.get("payloads", [])
        signatures: list[str] = self._nosqli.get("error_signatures", [])

        for payload in payloads:
            query = self._build_query(field.name, arg, payload, selection)
            try:
                resp = await req.graphql(query)
                body = resp.text
                matched = next((s for s in signatures if s.lower() in body.lower()), None)
                if matched:
                    return [
                        self.finding(
                            title=f"NoSQL Injection — {field.name}.{arg}",
                            severity="high",
                            confidence="tentative",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' may be "
                                f"vulnerable to NoSQL injection. A MongoDB/document-store "
                                f"error signature was detected in the server response."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"Signature: '{matched}'. Response: {truncate(body, 400)}",
                            remediation=(
                                "Validate and sanitize all inputs before passing them to the "
                                "database layer. Use typed schemas (e.g., Mongoose) with strict "
                                "validation. Never pass raw GraphQL argument objects to MongoDB."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # Command Injection
    # ------------------------------------------------------------------ #

    async def _test_cmdi(
        self, ctx: RunContext, req: Requester, field: GraphQLField, arg: str, selection: str
    ) -> list[Finding]:
        """Confirm command injection with a *differential* time-based oracle.

        A delay alone is not proof, and the delay must be measured cleanly:

        * **Clean round-trip.** We use ``req.timed_graphql`` which clocks only the
          HTTP round trip (after the concurrency slot is acquired, single attempt,
          no retry). The naive approach of timing across ``req.graphql`` instead
          measures the wait to *acquire* the semaphore plus any retry backoff a
          different request is performing while holding it — so an unrelated
          request retrying for 2+4s makes every queued field look like it slept.
        * **Serialized probes.** ``_cmdi_lock`` ensures no two fields' timing
          sequences overlap, so one field's genuine sleep can't inflate another's.
        * **Differential, reproduced twice.** Each sleep sample is paired with a
          benign control; only a delay specific to *this* field (sleep − control
          ≳ the sleep duration) confirms, and it must hold on a second pair.
        """
        threshold = _CMDI_SLEEP_SECONDS - 1  # margin for jitter

        async with self._cmdi_lock:
            for payload in _CMDI_SLEEP_PAYLOADS:
                delayed = await self._timed_request(req, field.name, arg, payload, selection)
                if delayed is None or delayed < threshold:
                    continue  # no delay at all → cheap bail, no shell ran

                control = await self._timed_request(req, field.name, arg, "gqlx", selection)
                if control is None or delayed - control < threshold:
                    continue  # the delay was ambient congestion, not this field

                # Reproduce the differential to rule out a one-off scheduling artefact.
                confirm = await self._timed_request(req, field.name, arg, payload, selection)
                control2 = await self._timed_request(req, field.name, arg, "gqlx", selection)
                if confirm is None or control2 is None or confirm - control2 < threshold:
                    continue

                return [
                    self.finding(
                        title=f"Command Injection — {field.name}.{arg}",
                        severity="critical",
                        confidence="confirmed",
                        description=(
                            f"The argument '{arg}' on field '{field.name}' is vulnerable "
                            f"to OS command injection. A '{payload}' payload reproducibly "
                            f"delayed the response by ~{_CMDI_SLEEP_SECONDS}s relative to a "
                            f"benign control sent in the same window, proving "
                            f"attacker-controlled shell execution (not ambient load)."
                        ),
                        endpoint=ctx.url,
                        payload=payload,
                        evidence=(
                            f"Sleep {delayed:.1f}s/{confirm:.1f}s vs control "
                            f"{control:.1f}s/{control2:.1f}s in the same window "
                            f"(Δ≈{_CMDI_SLEEP_SECONDS}s isolates the field-specific delay)."
                        ),
                        remediation=(
                            "Never pass user-controlled input to shell commands. Use "
                            "subprocess with argument lists (not shell=True). Prefer "
                            "library functions over system calls."
                        ),
                    )
                ]

        return []

    async def _timed_request(
        self, req: Requester, field: str, arg: str, value: str, selection: str
    ) -> float | None:
        """Clean round-trip timing for one probe, or None on transport error.

        Delegates to ``req.timed_graphql`` so the measurement excludes
        semaphore-acquisition wait and retry backoff (see ``_test_cmdi``).
        """
        query = self._build_query(field, arg, value, selection)
        try:
            resp, elapsed = await req.timed_graphql(query)
        except (RequestError, AttributeError):
            return None
        if resp is None:
            return None
        return float(elapsed)

    # ------------------------------------------------------------------ #
    # SSTI
    # ------------------------------------------------------------------ #

    async def _test_ssti(
        self, ctx: RunContext, req: Requester, field: GraphQLField, arg: str, selection: str
    ) -> list[Finding]:
        """Confirm SSTI by arithmetic differential.

        For each template wrapper we require BOTH operand pairs to evaluate
        correctly (7*7 -> 49 and 6*6 -> 36). Demanding two independent correct
        evaluations rules out a stray "49" appearing in an unrelated response.
        """
        for left, right in _SSTI_WRAPPERS:
            all_evaluated = True
            sample = ""
            for a, b, expected in _SSTI_PAIRS:
                payload = f"{left}{a}*{b}{right}"
                query = self._build_query(field.name, arg, payload, selection)
                try:
                    resp = await req.graphql(query)
                    body = resp.text
                except (RequestError, AttributeError):
                    all_evaluated = False
                    break
                # The literal expression must NOT be reflected verbatim while the
                # computed result IS present — that is what proves evaluation.
                if expected not in body or f"{a}*{b}" in body:
                    all_evaluated = False
                    break
                sample = truncate(body, 300)

            if all_evaluated:
                return [
                    self.finding(
                        title=f"Server-Side Template Injection — {field.name}.{arg}",
                        severity="critical",
                        confidence="confirmed",
                        description=(
                            f"The argument '{arg}' on field '{field.name}' is rendered "
                            f"inside a server-side template engine using the "
                            f"'{left}…{right}' syntax. Two arithmetic probes (7*7→49, "
                            f"6*6→36) both evaluated, confirming template injection, which "
                            f"commonly escalates to remote code execution."
                        ),
                        endpoint=ctx.url,
                        payload=f"{left}7*7{right}",
                        evidence=f"Both 7*7→49 and 6*6→36 evaluated. Sample: {sample}",
                        remediation=(
                            "Never render user input inside a template. Pass data to "
                            "templates as context variables, not as part of the template string."
                        ),
                    )
                ]

        return []

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_query(field: str, arg: str, value: str, selection: str = "") -> str:
        escaped = value.replace('"', '\\"')
        return f'{{ {field}({arg}: "{escaped}"){selection} }}'
