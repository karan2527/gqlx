"""
Cognito authentication helper for fullpwn.
Scrapes JS bundles for AppSync/Cognito config, drives OTP or password auth.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

import httpx


@dataclass
class AppConfig:
    graphql_endpoint: str
    user_pool_id: str
    client_id: str
    region: str


_GQL_PATS = [
    re.compile(
        r'aws_appsync_graphqlEndpoint["\'\s:]+["\']?(https://[^\s"\'>,;]+)',
        re.I,
    ),
    re.compile(r'"graphqlEndpoint"\s*:\s*"(https://[^"]+)"'),
    re.compile(r'graphqlEndpoint\s*[:=]\s*["\']?(https://[^\s"\'>,;]+)'),
]

_POOL_PATS = [
    re.compile(r'aws_user_pools_id["\'\s:]+["\']?([a-z]{2}-[a-z]+-\d_\w+)["\']?', re.I),
    re.compile(r'"userPoolId"\s*:\s*"([a-z]{2}-[a-z]+-\d_\w+)"', re.I),
    re.compile(r'userPoolId\s*[:=]\s*["\']([a-z]{2}-[a-z]+-\d_\w+)["\']', re.I),
]

_CLIENT_PATS = [
    re.compile(r'aws_user_pools_web_client_id["\'\s:]+["\']?([0-9a-z]{10,80})["\']?', re.I),
    re.compile(r'"userPoolWebClientId"\s*:\s*"([0-9a-z]{10,80})"', re.I),
    re.compile(r'userPoolWebClientId\s*[:=]\s*["\']([0-9a-z]{10,80})["\']', re.I),
]


def _first_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(1)
    return None


def _collect_bundle_urls(html: str, base_url: str) -> list[str]:
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
    urls: list[str] = []
    for src in srcs:
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("//"):
            urls.append(f"{parsed.scheme}:{src}")
        elif src.startswith("/"):
            urls.append(f"{origin}{src}")
        else:
            urls.append(f"{origin}/{src.lstrip('/')}")
    return urls


def scrape_app_config(
    website_url: str,
    timeout: int = 30,
    endpoint_override: str | None = None,
    pool_id_override: str | None = None,
    client_id_override: str | None = None,
) -> AppConfig:
    """
    Fetch website + JS bundles, extract AppSync endpoint and Cognito config.
    Manual overrides skip the corresponding scrape.
    """
    if not website_url.startswith("http"):
        website_url = f"https://{website_url}"

    all_text = ""
    bundle_urls: list[str] = []

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(website_url)
        resp.raise_for_status()
        html = resp.text
        all_text = html

        bundle_urls = _collect_bundle_urls(html, website_url)
        for bundle_url in bundle_urls:
            try:
                js = client.get(bundle_url)
                if js.status_code == 200:
                    all_text += js.text
            except Exception:
                continue

    gql_endpoint = endpoint_override or _first_match(_GQL_PATS, all_text)
    pool_id = pool_id_override or _first_match(_POOL_PATS, all_text)
    client_id = client_id_override or _first_match(_CLIENT_PATS, all_text)

    missing = [
        name
        for name, val in [
            ("graphql_endpoint", gql_endpoint),
            ("user_pool_id", pool_id),
            ("client_id (aws_user_pools_web_client_id)", client_id),
        ]
        if not val
    ]
    if missing:
        raise ValueError(
            f"Could not extract from JS bundles: {', '.join(missing)}.\n"
            f"Searched {len(bundle_urls)} bundle(s). "
            "Use --endpoint / --pool-id / --client-id to provide them manually, "
            "or fall back to 'autopwn' with a pasted token."
        )

    assert gql_endpoint is not None
    assert pool_id is not None
    assert client_id is not None
    region = pool_id.split("_")[0]
    return AppConfig(
        graphql_endpoint=gql_endpoint,
        user_pool_id=pool_id,
        client_id=client_id,
        region=region,
    )


class CognitoFlowDisabledError(RuntimeError):
    """Raised when a Cognito auth flow is not enabled on the app client."""


def _cognito_post(region: str, target: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
    url = f"https://cognito-idp.{region}.amazonaws.com/"
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            url,
            json=body,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": f"AmazonCognitoIdentityProviderService.{target}",
            },
        )
        data = cast(dict[str, Any], resp.json())
        if resp.status_code != 200:
            error_type = data.get("__type", "")
            msg = data.get("message") or data.get("Message") or str(data)
            # Pool client doesn't have this flow enabled
            if error_type in ("UnknownOperationException", "NotAuthorizedException") and (
                "flow" in msg.lower() or error_type == "UnknownOperationException"
            ):
                raise CognitoFlowDisabledError(f"{body.get('AuthFlow', target)} not enabled: {msg}")
            raise RuntimeError(f"Cognito {target} request failed ({resp.status_code}): {msg}")
        return data


def initiate_otp_auth(client_id: str, region: str, email: str, timeout: int = 30) -> str:
    """
    Start Cognito CUSTOM_AUTH (OTP) flow.
    Returns the session string needed for the challenge step.
    """
    data = _cognito_post(
        region,
        "InitiateAuth",
        {
            "AuthFlow": "CUSTOM_AUTH",
            "ClientId": client_id,
            "AuthParameters": {"USERNAME": email},
        },
        timeout,
    )
    challenge = data.get("ChallengeName")
    session = data.get("Session")
    if challenge != "CUSTOM_CHALLENGE" or not session:
        raise RuntimeError(
            f"Expected CUSTOM_CHALLENGE, got '{challenge}'. "
            "This app may not use OTP; try --auth-flow password or paste "
            "a token via 'autopwn'."
        )
    return cast(str, session)


def complete_otp_auth(
    client_id: str, region: str, email: str, session: str, otp: str, timeout: int = 30
) -> str:
    """Complete CUSTOM_CHALLENGE with OTP. Returns IdToken."""
    data = _cognito_post(
        region,
        "RespondToAuthChallenge",
        {
            "ChallengeName": "CUSTOM_CHALLENGE",
            "ClientId": client_id,
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": email,
                "ANSWER": otp.strip(),
            },
        },
        timeout,
    )
    auth = data.get("AuthenticationResult")
    if not auth:
        raise RuntimeError(
            f"Authentication failed; no AuthenticationResult. Wrong OTP? Response: {data}"
        )
    id_token = auth.get("IdToken")
    if not id_token:
        raise RuntimeError("No IdToken in AuthenticationResult.")
    return cast(str, id_token)


def password_auth(client_id: str, region: str, email: str, password: str, timeout: int = 30) -> str:
    """USER_PASSWORD_AUTH flow. Returns IdToken. For non-OTP Cognito apps."""
    data = _cognito_post(
        region,
        "InitiateAuth",
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client_id,
            "AuthParameters": {
                "USERNAME": email,
                "PASSWORD": password,
            },
        },
        timeout,
    )
    auth = data.get("AuthenticationResult")
    if not auth:
        challenge = data.get("ChallengeName", "unknown")
        raise RuntimeError(
            f"Got challenge '{challenge}' instead of direct auth. "
            "MFA/SRP not supported; paste token manually via 'autopwn'."
        )
    id_token = auth.get("IdToken")
    if not id_token:
        raise RuntimeError("No IdToken in AuthenticationResult (password flow).")
    return cast(str, id_token)


class AuthResult:
    """Returned by auto_auth with the IdToken and which flow succeeded."""

    def __init__(self, id_token: str, flow_used: str) -> None:
        self.id_token = id_token
        self.flow_used = flow_used


def auto_auth(
    client_id: str,
    region: str,
    email: str,
    timeout: int = 30,
    prompt_fn: Callable[[str], str] | None = None,
) -> AuthResult:
    """Try OTP and password-based Cognito authentication flows."""
    ask = prompt_fn if prompt_fn is not None else input

    try:
        session = initiate_otp_auth(client_id, region, email, timeout)
        otp = ask("Enter OTP (sent to your email): ")
        id_token = complete_otp_auth(client_id, region, email, session, otp, timeout)
        return AuthResult(id_token=id_token, flow_used="CUSTOM_AUTH (OTP)")
    except CognitoFlowDisabledError:
        pass

    try:
        password = ask("Password: ")
        id_token = password_auth(client_id, region, email, password, timeout)
        return AuthResult(id_token=id_token, flow_used="USER_PASSWORD_AUTH")
    except CognitoFlowDisabledError:
        pass

    raise RuntimeError(
        "Neither CUSTOM_AUTH nor USER_PASSWORD_AUTH is enabled on this Cognito app client.\n"
        "The pool likely uses USER_SRP_AUTH (SRP is not supported by fullpwn).\n"
        "Workaround: log in via the browser, copy the IdToken from DevTools, "
        "and run: gqlx autopwn <endpoint> -t <token>"
    )
