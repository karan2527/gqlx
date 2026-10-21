from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from gqlx.cli import _second_identity_headers
from gqlx.core.enumerator import Enumerator
from gqlx.core.requester import Requester
from gqlx.core.scanner import Scanner
from gqlx.modules.base import BaseModule, ModuleMetadata
from gqlx.utils.config import load_config
from gqlx.utils.models import (
    GraphQLArgument,
    GraphQLField,
    GraphQLSchema,
    GraphQLType,
    RunContext,
    ScanConfig,
    ScanResult,
)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _local_schema() -> GraphQLSchema:
    user = GraphQLType(
        name="User",
        kind="OBJECT",
        fields=[
            GraphQLField(name="id", field_type="ID!"),
            GraphQLField(name="name", field_type="String!"),
        ],
    )
    return GraphQLSchema(
        queries=[
            GraphQLField(name="health", field_type="String!"),
            GraphQLField(name="users", field_type="[User!]!"),
            GraphQLField(
                name="user",
                field_type="User",
                args=[GraphQLArgument(name="id", type_name="ID!", is_required=True)],
            ),
        ],
        types={"User": user},
    )


def test_enumerator_builds_valid_local_lab_operations() -> None:
    enumerator = Enumerator(None, schema=_local_schema())  # type: ignore[arg-type]
    fields = enumerator.schema.queries if enumerator.schema else []

    assert enumerator._build_query(fields[0], "query") == "query { health }"
    assert enumerator._build_query(fields[1], "query") == "query { users { id name } }"
    assert enumerator._build_query(fields[2], "query") == 'query { user(id: "test") { id name } }'


def test_enumerator_handles_input_objects_and_enums() -> None:
    schema = GraphQLSchema(
        types={
            "Status": GraphQLType(name="Status", kind="ENUM", enum_values=["ACTIVE"]),
            "Filter": GraphQLType(
                name="Filter",
                kind="INPUT_OBJECT",
                input_fields=[
                    GraphQLArgument(name="status", type_name="Status!", is_required=True),
                    GraphQLArgument(name="limit", type_name="Int", is_required=False),
                ],
            ),
        }
    )
    enumerator = Enumerator(None, schema=schema)  # type: ignore[arg-type]
    field = GraphQLField(
        name="search",
        field_type="String",
        args=[GraphQLArgument(name="filter", type_name="Filter!", is_required=True)],
    )

    assert enumerator._build_query(field, "query") == (
        "query { search(filter: {status: ACTIVE, limit: 10}) }"
    )


def test_enumerator_classifiers_ignore_words_in_data() -> None:
    body = json.dumps({"data": {"message": "forbidden variable expected type"}})
    assert not Enumerator._is_auth_error(body)
    assert not Enumerator._is_gql_error(body)
    errors = json.dumps({"errors": [{"message": "Forbidden"}]})
    assert Enumerator._is_auth_error(errors)
    assert Enumerator._is_gql_error(errors)


def test_second_identity_preserves_bearer_scheme() -> None:
    assert _second_identity_headers("token-b", {"Authorization": "Bearer token-a"}) == {
        "Authorization": "Bearer token-b"
    }
    assert _second_identity_headers("token-b", {"Authorization": "token-a"}) == {
        "Authorization": "token-b"
    }
    assert _second_identity_headers("Bearer token-b", {"authorization": "BEARER token-a"}) == {
        "Authorization": "Bearer token-b"
    }
    assert _second_identity_headers("  ", {"Authorization": "Bearer token-a"}) == {}


def test_second_identity_cookies_are_propagated_without_exposing_credentials(capsys) -> None:
    config = ScanConfig(
        url="https://example.test/graphql",
        headers={"Authorization": "Bearer token-a"},
        headers_b=_second_identity_headers("token-b", {"Authorization": "Bearer token-a"}),
        cookies={"session": "session-a"},
        cookies_b={"session": "session-b"},
    )

    second = RunContext(
        config=config,
        result=ScanResult(target=config.url),
        requester=object(),
    ).second_identity_config()

    assert second.headers == {"Authorization": "Bearer token-b"}
    assert second.cookies == {"session": "session-b"}
    assert "token-a" not in repr(second.headers)
    assert "session-a" not in repr(second.cookies)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_config_sections_keep_distinct_max_depths(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "http:\n  verify_ssl: false\nscan:\n  max_depth: 3\ndos:\n  max_depth: 15\n",
        encoding="utf-8",
    )
    config = load_config(str(config_file))
    assert config["max_depth"] == 3
    assert config["dos_max_depth"] == 15
    assert config["verify_ssl"] is False


def test_requester_passes_http_configuration(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    config = ScanConfig(
        url="https://example.test/graphql",
        timeout=7,
        concurrency=2,
        max_retries=4,
        verify_ssl=False,
        follow_redirects=False,
        user_agent="test-agent",
        proxy="http://proxy.test:8080",
    )
    requester = Requester(config)
    _run(requester.__aenter__())
    assert captured["timeout"] == httpx.Timeout(7)
    assert captured["verify"] is False
    assert captured["follow_redirects"] is False
    assert captured["headers"]["User-Agent"] == "test-agent"
    assert captured["proxy"] == "http://proxy.test:8080"
    assert requester.max_retries == 4
    _run(requester.__aexit__(None, None, None))


class _FailingModule(BaseModule):
    metadata = ModuleMetadata(name="failing", description="test")

    async def run(self, ctx: RunContext) -> list:
        raise RuntimeError("secret request details")


def test_scanner_records_module_failures_without_exposing_exception(monkeypatch) -> None:
    scanner = Scanner(ScanConfig(url="https://example.test/graphql"))
    result = ScanResult(target=scanner.config.url)
    ctx = RunContext(config=scanner.config, result=result, requester=object())

    findings = _run(scanner._run_modules([_FailingModule()], ctx))

    assert findings == []
    assert result.module_status == {"failing": "failed"}
    assert result.module_errors == {"failing": "RuntimeError"}
