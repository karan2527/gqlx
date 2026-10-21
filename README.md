# gqlx

## GraphQL Security Testing Framework

`gqlx` is a command-line security testing framework for GraphQL APIs. It
discovers a target's GraphQL schema, maps its queries and mutations, generates
type-aware GraphQL operations, sends carefully selected security test
requests, and produces a report that can be reviewed by developers, security
engineers, and authorized penetration testers.

It supports standard GraphQL APIs as well as common AWS AppSync and Cognito
deployments.

> **Important:** Use `gqlx` only against systems that you own or have
> explicit written permission to test.

## What gqlx does

A typical scan follows this workflow:

1. **Connects to the GraphQL endpoint** using the supplied headers, cookies,
   token, proxy, timeout, and concurrency settings.
2. **Discovers the schema** through GraphQL introspection when it is enabled.
   The schema is parsed into queries, mutations, fields, arguments, types, and
   relationships.
3. **Builds valid GraphQL operations** based on the discovered field types.
   This lets the scanner test real application fields instead of sending only
   generic malformed requests.
4. **Runs the selected security modules** against string, ID, URL, and
   authentication-related fields. Modules are bounded by the configured
   concurrency and rate limit.
5. **Confirms potential vulnerabilities** using response, timing, or
   cross-identity comparisons where possible.
6. **Writes a report** in HTML, JSON, or Markdown format. Module failures are
   recorded explicitly and partial results are reported as partial.

If introspection is disabled, `gqlx` tries the following discovery methods:

1. Full introspection.
2. Header-based introspection bypass probes.
3. Partial introspection.
4. Wordlist-based field discovery.

Results identify the discovery method as `full`, `bypass`, `partial`,
`wordlist`, or `none`, so a report does not imply complete schema coverage
when discovery was incomplete.

## Detection philosophy

`gqlx` is designed to reduce false positives. It distinguishes between:

- **Confirmed findings**: an oracle produced repeatable evidence that supports
  the vulnerability claim.
- **Tentative findings**: a heuristic or signal that requires manual review.

Examples of confirmation oracles include:

| Test area | Confirmation approach |
| --- | --- |
| Command injection | Reproducible time-based delay |
| Server-side template injection (SSTI) | Arithmetic differential evaluation |
| BOLA / IDOR | Cross-identity response differential |
| Tenant isolation | Cross-identity `organization_id` differential |
| SSRF | Internal-target signature without a matching benign-control result |
| Missing authentication | Sensitive data returned after credentials are removed |
| Invalid JWT or `alg=none` behavior | Canary data returned from an authentication-gated field |

The scanner does not treat every error message or unusual response as a
confirmed vulnerability.

## Installation

### Requirements

- Python 3.12 or newer
- Network access to the authorized GraphQL target
- Written authorization to perform the assessment

### Install from a checkout

```powershell
git clone https://github.com/karan2527/gqlx.git
cd gqlx
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate the virtual environment before using the
`gqlx` command. Activation adds the environment's `Scripts` directory to the
current shell's `PATH`:

```powershell
.\.venv\Scripts\Activate.ps1
gqlx --version
```

If PowerShell prevents script execution for the current user, use the
following user-scoped setting and then activate the environment again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Alternatively, the CLI can always be run without activation:

```powershell
.\.venv\Scripts\python.exe -m gqlx.cli --help
```

## Basic usage

### Show help and available modules

```powershell
gqlx --help
gqlx list-modules
```

### Run a full scan

The following command scans a GraphQL endpoint and writes an HTML report:

```powershell
gqlx scan https://target.example/graphql `
  -H "Authorization: Bearer YOUR_TOKEN" `
  -o report.html
```

Use `-H` more than once when multiple headers are required:

```powershell
gqlx scan https://target.example/graphql `
  -H "Authorization: Bearer YOUR_TOKEN" `
  -H "X-Api-Key: YOUR_API_KEY" `
  -f json `
  -o report.json
```

### Provide a second identity for authorization testing

BOLA, IDOR, and tenant-isolation checks require two identities for a meaningful
cross-user comparison. Supply the second token with `--token-b`:

```powershell
gqlx scan https://target.example/graphql `
  -H "Authorization: Bearer TOKEN_A" `
  --token-b "TOKEN_B" `
  --modules bola,tenant_isolation `
  -f html `
  -o authorization-report.html
```

The first identity is used as the baseline. The second identity is used to
check whether data belonging to the first identity or tenant is exposed.

The authentication scheme is inherited from the primary `Authorization`
header:

- The primary `Authorization` format is reused for the second identity.
- A primary value without a prefix remains a value without a prefix.
- A prefix included with `--token-b` is normalized before the request.
The actual second token is retained only in the request configuration. It is
not printed or written to reports by the identity-header helper.

For cookie-authenticated identities, provide separate cookie strings:

```powershell
gqlx scan https://target.example/graphql `
  -c "session=SESSION_A" `
  --cookie-b "session=SESSION_B" `
  --modules bola,tenant_isolation `
  -o cookie-authorization-report.html
```

### Use cookies or a proxy

```powershell
# Cookie-authenticated target
gqlx scan https://target.example/graphql `
  -c "session=SESSION_VALUE; csrf=CSRF_VALUE"

# Route requests through Burp Suite or another HTTP proxy
gqlx scan https://target.example/graphql `
  -x http://127.0.0.1:8080
```

### Discover and save the schema only

Use `introspect` when you want schema information without running the
vulnerability modules:

```powershell
gqlx introspect https://target.example/graphql -o schema.json
```

The output includes the discovered operations, types, fields, arguments, and
the discovery method used.

## Commands

### `scan`

Runs the full security scanning workflow.

```text
gqlx scan [OPTIONS] URL
```

Important options:

| Option | Purpose |
| --- | --- |
| `-H, --header TEXT` | Add an HTTP header; repeatable |
| `--token-b TEXT` | Supply a second bearer token for cross-identity checks |
| `-c, --cookie TEXT` | Add a cookie string |
| `--cookie-b TEXT` | Add cookies for the second identity |
| `-x, --proxy TEXT` | Use an HTTP or HTTPS proxy |
| `-m, --modules TEXT` | Comma-separated module names |
| `-o, --output TEXT` | Write the report to a file |
| `-f, --format` | Select `html`, `json`, or `markdown` |
| `-t, --timeout INTEGER` | Request timeout in seconds |
| `-w, --workers INTEGER` | Maximum concurrent workers |
| `-r, --rate-limit FLOAT` | Delay between requests in seconds |
| `--wordlist TEXT` | Use a custom field-discovery wordlist |
| `--aggressive` | Enable resource-intensive DoS checks |
| `-v, --verbose` | Enable verbose logging |
| `--config TEXT` | Load a custom YAML configuration file |

`--timeout`, `--workers`, and `--rate-limit` reject invalid negative or zero
values where those values would be unsafe. TLS certificate verification is
enabled by default and can be configured through YAML.

View the complete option list with:

```powershell
gqlx scan --help
```

### `introspect`

Discovers and prints or saves the target schema:

```text
gqlx introspect [OPTIONS] URL
```

The command reports the discovery method and the number of parsed queries,
mutations, subscriptions, and types. It does not run vulnerability modules.

### `enum`

Performs deeper GraphQL enumeration by sending discovered operations and
mapping their behavior. Use it only on authorized targets because it can
generate substantially more requests than a normal schema discovery.

Enumeration generates selections for object and list return types and
constructs required scalar, enum, list, and input-object arguments. A
`null` object result or empty list is not treated as accessible data. Use
`--mutations` only when mutation execution is explicitly approved; mutation
operations can change application state.

### `autopwn`

Runs an automated workflow that attempts to discover application context,
decode supplied token information, and identify user or organization details.
This command is intended for authorized assessment workflows where the
required target and authentication information are available.

### `fullpwn`

Runs the end-to-end website and authentication discovery workflow for supported
AWS Cognito and AppSync deployments. Review its help output before use:

```powershell
gqlx fullpwn --help
```

`fullpwn` may prompt for authentication data and is intended for supported
AWS Cognito/AppSync workflows. Do not pass real credentials in shell history
or bug reports.

## Security modules

The standard modules are:

| Module | What it checks |
| --- | --- |
| `info_disclosure` | Introspection exposure, debug responses, stack traces, and version leakage |
| `injection` | SQL injection, NoSQL injection, command injection, and SSTI indicators in string arguments |
| `bola` | Object-level authorization problems in ID-based fields using identity comparisons |
| `auth` | Missing authentication and invalid-token behavior using data-leak oracles |
| `ssrf` | URL arguments that may cause server-side requests to internal or cloud metadata targets |
| `tenant_isolation` | Cross-tenant access through `organization_id`-related fields |
| `dos` | Query-depth, alias-overloading, and batch-size protections |

The `dos` module is disabled unless `--aggressive` is supplied:

```powershell
gqlx scan https://target.example/graphql --aggressive --modules dos
```

Aggressive testing can place additional load on the target. Obtain approval
for that scope separately before enabling it.

When no `--modules` list is supplied, the scanner resolves the registered
modules and skips modules marked as aggressive unless `--aggressive` is set.
Use `gqlx list-modules` to inspect the registry and each module's aggressive
status.

## Reports and findings

Reports can be written in three formats:

```powershell
gqlx scan https://target.example/graphql -f html -o report.html
gqlx scan https://target.example/graphql -f json -o report.json
gqlx scan https://target.example/graphql -f markdown -o report.md
```

Reports contain the target, scan timestamps, discovery status, modules run,
module status, failed-module types, findings, evidence, request payloads where
available, confidence, severity, and remediation guidance. Exception details
are not included in the structured module-failure fields.

The JSON format is useful for CI pipelines and custom processing. HTML is
intended for interactive review, while Markdown is convenient for tickets and
source-controlled assessment notes.

## Configuration

The repository includes [`config.yaml`](config.yaml) with defaults for:

- HTTP timeout, concurrency, retries, redirects, TLS verification, and rate
  limiting
- User agent and proxy settings
- Schema traversal depth and BOLA ID probing
- Independent scan and DoS depth limits
- Conservative DoS alias and batch limits
- Report format and informational findings
- Logging level

Pass another configuration file with `--config`:

```powershell
gqlx scan https://target.example/graphql --config .\my-config.yaml
```

CLI options take precedence over configuration-file values.

The scan traversal depth and DoS payload depth are independent settings:

```yaml
scan:
  max_depth: 3

dos:
  max_depth: 15
```

## Local development and testing

The project includes a small local GraphQL server for safe integration
testing. Start it in one PowerShell window:

```powershell
.\.venv\Scripts\python.exe .\local_graphql_lab.py
```

The lab provides:

- GraphQL endpoint: `http://127.0.0.1:8765/graphql`
- Health endpoint: `http://127.0.0.1:8765/health`
- `health`, `users`, and `user(id: ID!)` queries
- Valid example user IDs `1` and `2`
- An example `createNote(text: String!)` mutation

The lab is intended for safe request and operation-generation checks. The
example mutation should not be executed unless its side effects are
specifically intended.

In another PowerShell window, run:

```powershell
.\.venv\Scripts\Activate.ps1
gqlx introspect http://127.0.0.1:8765/graphql -o local-schema.json
gqlx scan http://127.0.0.1:8765/graphql -f json -o local-report.json
```

Run the automated checks with:

```powershell
pytest -q
ruff check gqlx tests
ruff format --check gqlx tests
mypy gqlx
python -m pip check
python -m compileall -q gqlx local_graphql_lab.py
```

The current regression baseline is 47 passing tests. These checks establish
local correctness and packaging consistency; they do not prove that every
security detector is accurate against a real production application.

## Verification boundaries

The project has been verified locally for:

- Type-aware query and mutation construction.
- Required scalar and input-object argument generation.
- Null and empty-result classification.
- Authorization-format and bare-token second-identity propagation using dummy credentials.
- Second-identity cookie propagation.
- HTTP timeout, retry, proxy, redirect, user-agent, concurrency, rate-limit,
  and TLS configuration wiring.
- Structured GraphQL error classification.
- Explicit failed-module and partial-report handling.
- JSON, Markdown, and HTML report generation.

The following require an authorized target, suitable test accounts, or
specialized infrastructure and are not established by the local test suite:

- Real BOLA/IDOR or tenant-isolation vulnerability detection.
- Cognito authentication success and failure flows.
- SQL/NoSQL injection, command injection, SSTI, SSRF, or DoS impact against a
  real service.
- Production proxy behavior, TLS failures, redirect behavior, and rate-limit
  impact.
- Completeness of a target's wordlist or partial-discovery results.

Treat findings as assessment evidence, not as proof that a target is secure.
Manually validate tentative findings and any result obtained from partial,
wordlist, or unavailable discovery.

## Project layout

```text
gqlx/
├── cli.py                 Command-line interface
├── core/
│   ├── cognito_auth.py    AWS Cognito discovery and authentication helpers
│   ├── enumerator.py      Deep operation enumeration
│   ├── introspector.py    GraphQL schema discovery
│   ├── parser.py          Schema parsing and normalization
│   ├── requester.py       Async HTTP, retries, proxy, and rate limiting
│   └── scanner.py         Scan orchestration
├── modules/               Vulnerability detection modules
├── output/                Report generation and templates
├── payloads/              Test payloads and wordlists
└── utils/                 Configuration, logging, helpers, and data models
```

## Safety and legal use

`gqlx` is a security testing tool, not an exploitation service. Always:

1. Confirm that the target and requested test scope are covered by written
   authorization.
2. Use test accounts and non-production environments whenever possible.
3. Agree on request-rate and aggressive-testing limits in advance.
4. Protect tokens, cookies, reports, and captured responses as sensitive
   information.
5. Stop the scan if it causes unexpected impact.

No destructive payloads are intentionally included. Even non-destructive
security tests can expose sensitive data or create load, so authorization and
responsible handling are required.

## License

MIT License. See the project license information for details.
