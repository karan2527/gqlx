"""
Auth Module
Tests for missing authentication, broken auth checks, and JWT weaknesses.

Detection is by DATA ORACLE, not error strings. A field is judged reachable
only if the response carries non-empty object data for it. This is independent
of how a given deployment signals rejection (AppSync returns HTTP 401
UnauthorizedException for one Cognito pool, a resolver may return
HTTP 200 + data:null for another, a field directive may null a single field) —
all of which would defeat keyword matching but none of which leak data.

Token-acceptance tests (alg=none, garbage token) only run when a genuine
auth-gated "canary" field exists: one that returns data with the real token and
nothing without it. Probing __typename — which resolves for everyone — proves
nothing and is never used as an oracle.
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

from gqlx.core.requester import Requester, RequestError
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.helpers import truncate
from gqlx.utils.logger import get_logger
from gqlx.utils.models import Finding, GraphQLField, GraphQLSchema, RunContext

logger = get_logger(__name__)

# How many no-required-arg operations to probe (avoid hammering large schemas).
_MAX_FIELDS = 15

_INVALID_TOKENS = [
    "Bearer invalid.token.here",
    "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
]


def _field_data(body: str, field_name: str) -> object | None:
    """Return the non-empty `data.<field>` value, or None.

    None means "no usable object data came back" — whether due to an auth
    rejection, a null field, or a transport error. That is exactly the signal
    the oracle needs, and it does not depend on any error wording.
    """
    try:
        data = (json.loads(body) or {}).get("data")
    except (json.JSONDecodeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    val = data.get(field_name)
    if val is None or val == {} or val == []:
        return None
    return cast(object, val)


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return cast(dict[str, Any], json.loads(base64.urlsafe_b64decode(parts[1] + "==")))
    except Exception:
        return None


def _forge_none_alg_jwt(original_token: str) -> str | None:
    """Forge an alg=none JWT (unsigned) from a real token's header/payload."""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def _callable_fields(schema: GraphQLSchema) -> list[GraphQLField]:
    """Operations callable with no arguments (so the query is valid as-is)."""
    return [f for f in schema.all_operations() if not any(a.is_required for a in f.args)]


class AuthModule(BaseModule):
    """Tests for missing and broken authentication on GraphQL operations."""

    metadata = ModuleMetadata(
        name="auth",
        description="Tests missing auth and token validation via a data-leak oracle",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://portswigger.net/web-security/graphql/security-considerations",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        auth_header = ctx.config.headers.get("Authorization") or ctx.config.headers.get(
            "authorization"
        )
        if not auth_header:
            logger.info("auth_no_credentials_configured")
            return []

        fields = _callable_fields(ctx.schema)[:_MAX_FIELDS]
        if not fields:
            logger.info("auth_no_callable_fields")
            return []

        selections = {f.name: ctx.schema.build_selection(f) for f in fields}

        # Baseline: which fields return data WITH the real token.
        authed = {
            f.name: await self._query(ctx.requester, ctx.url, f, selections[f.name]) for f in fields
        }

        stripped_headers = {
            k: v for k, v in ctx.config.headers.items() if k.lower() != "authorization"
        }
        anon_config = ctx.config.model_copy(update={"headers": stripped_headers})

        findings: list[Finding] = []
        canary: GraphQLField | None = None

        async with Requester(anon_config) as anon_req:
            for f in fields:
                anon_val = await self._query(anon_req, ctx.url, f, selections[f.name])
                if anon_val is not None:
                    findings.append(self._missing_auth_finding(ctx, f, anon_val))
                elif authed[f.name] is not None:
                    # Returns data with a token, nothing without one — a real
                    # auth gate we can use to test token validation.
                    canary = canary or f

        if canary is not None:
            findings += await self._check_token_validation(
                ctx, canary, selections[canary.name], auth_header
            )

        return findings

    def _missing_auth_finding(self, ctx: RunContext, field: GraphQLField, value: object) -> Finding:
        return self.finding(
            title=f"Unauthenticated Access — {field.name}",
            severity="high",
            confidence="confirmed",
            description=(
                f"The field '{field.name}' returns object data when the Authorization "
                f"header is removed entirely. The resolver does not enforce "
                f"authentication, so any anonymous client can read this data."
            ),
            endpoint=ctx.url,
            payload=f"{{ {field.name} }}  (no Authorization header)",
            evidence=f"Anonymous response data: {truncate(json.dumps(value), 300)}",
            remediation=(
                "Enforce authentication on every protected resolver (schema-level "
                "directive such as @aws_cognito_user_pools, or middleware). Never rely "
                "on the client to send credentials — verify server-side."
            ),
        )

    async def _check_token_validation(
        self, ctx: RunContext, canary: GraphQLField, selection: str, auth_header: str
    ) -> list[Finding]:
        """Against a confirmed auth-gated field, see if bogus tokens are accepted."""
        findings: list[Finding] = []

        # alg=none forgery (only meaningful for a Bearer JWT).
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            if _decode_jwt_payload(token):
                forged = _forge_none_alg_jwt(token)
                if forged:
                    val = await self._query_with_token(ctx, canary, selection, f"Bearer {forged}")
                    if val is not None:
                        findings.append(
                            self.finding(
                                title="JWT Algorithm Confusion — alg=none Accepted",
                                severity="critical",
                                confidence="confirmed",
                                description=(
                                    "An auth-gated field returned data when queried with a "
                                    "JWT whose algorithm was set to 'none' (no signature). "
                                    "An attacker can forge arbitrary claims (e.g. escalate "
                                    "role to admin) without the signing key."
                                ),
                                endpoint=ctx.url,
                                payload=f"Bearer {forged[:60]}…",
                                evidence=(
                                    f"Auth-gated field '{canary.name}' returned data with an "
                                    f"alg=none token: {truncate(json.dumps(val), 200)}"
                                ),
                                remediation=(
                                    "Reject alg=none in token validation. Pin the expected "
                                    "algorithm (e.g. RS256) when verifying. Cognito/AppSync "
                                    "verify signatures by default — this implies a custom, "
                                    "broken verifier in the path."
                                ),
                            )
                        )

        # Structurally-invalid / wrong-key tokens.
        for bad in _INVALID_TOKENS:
            val = await self._query_with_token(ctx, canary, selection, bad)
            if val is not None:
                findings.append(
                    self.finding(
                        title="Invalid Bearer Token Accepted",
                        severity="high",
                        confidence="confirmed",
                        description=(
                            "An auth-gated field returned data when queried with a clearly "
                            "invalid bearer token. Token validation is missing or does not "
                            "verify the signature, so credentials are not actually checked."
                        ),
                        endpoint=ctx.url,
                        payload=bad[:60],
                        evidence=(
                            f"Auth-gated field '{canary.name}' returned data with an invalid "
                            f"token: {truncate(json.dumps(val), 200)}"
                        ),
                        remediation=(
                            "Cryptographically validate every token before returning data. "
                            "Do not treat the mere presence of a bearer token as authentication."
                        ),
                    )
                )
                break

        return findings

    async def _query_with_token(
        self, ctx: RunContext, field: GraphQLField, selection: str, token: str
    ) -> object | None:
        cfg = ctx.config.model_copy(
            update={"headers": {**ctx.config.headers, "Authorization": token}}
        )
        async with Requester(cfg) as req:
            return await self._query(req, ctx.url, field, selection)

    async def _query(
        self, req: Requester, url: str, field: GraphQLField, selection: str
    ) -> object | None:
        query = f"{{ {field.name}{selection} }}"
        try:
            resp = await req.graphql(query, url=url)
        except (RequestError, AttributeError):
            return None
        return _field_data(resp.text, field.name)
