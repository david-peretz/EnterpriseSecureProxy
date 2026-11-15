# Enterprise Secure Proxy Web API

A configuration-driven, fail-closed HTTP proxy built with **C# / .NET 8, ASP.NET Core Web API, EF Core 8 and SQL Server**.

Callers ask for an *operation* by its configured key. The proxy decides - from trusted configuration only - **whether** the
request may be forwarded, **where** it goes (destination base URL), **how** (HTTP method, path template, headers, limits) and
**under which policy** (parameter rules, encryption, timeouts, audit). Nothing in the request can override that configuration,
and no request reaches an upstream before every validation and policy check has passed.

| Document | Content |
| --- | --- |
| `README.md` (this file) | Setup, running, testing, API contract, error codes, test traceability |
| `DESIGN-NOTES.md` | Architecture, request flow, security / reliability decisions and trade-offs |
| `DEFECT-REPORT.md` | Defects discovered and fixed during development and review, plus the defect classes prevented by design |
| `AI-USAGE.md` | AI assistance declaration |

---

## 1. Prerequisites

* [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (8.0.100 or later - see `global.json`)
* SQL Server 2019+ (any edition). The quickest option is Docker: `docker compose up -d` starts SQL Server 2022 on port 1433
  with the credentials used by `appsettings.json`.
* Optional: Visual Studio 2022 17.8+ or Rider / VS Code. The solution file is `EnterpriseSecureProxy.sln`.

> **Running the tests needs no database server.** The integration tests boot the real application in-process against a
> private SQLite database file (`Microsoft.EntityFrameworkCore.Sqlite`) and a mock destination.

## 2. Solution layout

```
EnterpriseSecureProxy.sln
├── src/SecureProxy.Api                 ASP.NET Core Web API (the proxy)
│   ├── Program.cs                      composition root, middleware pipeline
│   ├── Controllers/                    ProxyController (POST /api/proxy/execute), AdminController (/api/admin/*)
│   ├── Proxy/                          the request pipeline (see DESIGN-NOTES.md §2)
│   │   ├── ProxyExecutor.cs            orchestrates one execution end-to-end (start reading here)
│   │   ├── EnvelopeReader.cs           bounded body read + strict envelope validation
│   │   ├── OperationCatalog.cs         cached configuration lookup (consistency model in DESIGN-NOTES §6)
│   │   ├── ParameterValidator.cs       parameter rules (required / type / length / range / pattern / allowed values)
│   │   ├── UpstreamUriBuilder.cs       trusted URL construction + path traversal defences
│   │   ├── HeaderPolicy.cs             header allow-lists (request and response)
│   │   ├── UpstreamClient.cs           IHttpClientFactory client, timeout vs. cancellation, conservative retry
│   │   └── DestinationCircuitBreaker.cs circuit breaker + bounded concurrency
│   ├── Security/                       ISecretSource (key source abstraction), AES-256-GCM decryptor, admin API key filter
│   ├── Audit/                          audit recorder, bounded buffer, background writer
│   ├── Admin/                          configuration administration with optimistic concurrency + change history
│   ├── Domain/                         entities (Destination, Operation, ParameterRule, HeaderRule, EncryptionProfile, RequestLog, ConfigurationChange)
│   ├── Data/                           ProxyDbContext, entity configurations, EF Core migrations, demo seeder
│   ├── Configuration/                  strongly typed options (validated at start-up)
│   └── Infrastructure/                 correlation id middleware, structured log messages, health check
├── tests/SecureProxy.Tests             xUnit: integration tests (WebApplicationFactory + RecordingHandler) and unit tests
├── scripts/schema.sql                  idempotent SQL Server script generated from the EF Core migration
└── docker-compose.yml                  SQL Server 2022 for local development
```

## 3. Configuration

All settings live in `appsettings.json` (defaults) and `appsettings.Development.json`; every value can be overridden with
environment variables (`Proxy__MaxEnvelopeBytes=...`) or user-secrets.

| Section | Purpose | Notes |
| --- | --- | --- |
| `ConnectionStrings:ProxyDb` | SQL Server connection | matches `docker-compose.yml` by default |
| `Proxy` | envelope size cap, response size cap, timeout ceiling, config cache TTL, correlation header, allowed methods/schemes, response header allow-list | `AllowedDestinationSchemes` is `https` only outside Development |
| `Audit` | `ForwardingPolicy` (Mandatory / Buffered), `RejectionPolicy`, buffer size, flush interval | see DESIGN-NOTES §8 |
| `Admin` | admin API header name and key | **empty key = admin API disabled (404)** |
| `Resilience` | per-client rate limit (proxy and admin), max concurrent forwards, circuit breaker thresholds, retry switch | |
| `Database` | `MigrateOnStartup`, `SeedDemoData` | demo seed is enabled in Development |
| `Secrets:<name>` | secret values referenced from configuration as `cfg:<name>` | **never commit real values** - use user-secrets / environment / a secret-manager configuration provider |

### Secrets (local development)

The database stores only *references* (`cfg:demo-orders-v1`, `cfg:crm-api-key`). Values are resolved at runtime through
`ISecretSource`, whose default implementation reads `Secrets:<name>` from `IConfiguration`. Locally use user-secrets:

```bash
cd src/SecureProxy.Api
# admin API key (Development already has a throw-away default; override it if you like)
dotnet user-secrets set "Admin:ApiKey" "my-local-admin-key"
# 32-byte AES-256 key for the demo encrypted operation (base64)
dotnet user-secrets set "Secrets:demo-orders-v1" "$(openssl rand -base64 32)"
```

PowerShell equivalent for the key:

```powershell
$k = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($k)
dotnet user-secrets set "Secrets:demo-orders-v1" ([Convert]::ToBase64String($k))
```

In production, add a secret-manager configuration provider (e.g. Azure Key Vault) that maps into the `Secrets` section;
no code changes are required.

## 4. Running

```bash
docker compose up -d                      # SQL Server (skip if you have one; adjust the connection string)
dotnet run --project src/SecureProxy.Api  # Development profile: migrates the database and seeds demo configuration
```

The API listens on `http://localhost:5080` / `https://localhost:7443` (see `Properties/launchSettings.json`).
`src/SecureProxy.Api/SecureProxy.Api.http` contains ready-made requests (Visual Studio / VS Code REST Client).

The demo configuration points at `https://httpbin.org`, so a first smoke test needs nothing else:

```bash
curl -s http://localhost:5080/api/proxy/execute \
  -H "Content-Type: application/json" -H "X-Tenant-Id: tenant-42" \
  -d '{ "clientId": "echo.get", "json": { "urlId": "httpbin", "resourceId": "abc-123", "verbose": true } }'
```

Health: `GET /health`.

### Database schema

* `Database:MigrateOnStartup=true` (default) applies the EF Core migration in `src/SecureProxy.Api/Data/Migrations` at start-up.
* Alternatively run `scripts/schema.sql` (idempotent, generated from the same migration) or
  `dotnet ef database update --project src/SecureProxy.Api` (requires `dotnet tool install -g dotnet-ef`).
* After changing the model: `dotnet ef migrations add <Name> --project src/SecureProxy.Api --output-dir Data/Migrations`.

## 5. Tests

```bash
dotnet test
```

The suite (130 tests) runs in a few seconds and needs neither SQL Server nor network access:

* **Integration tests** (`tests/SecureProxy.Tests/*.cs`) use `WebApplicationFactory<Program>` with the production pipeline.
  The upstream `HttpClient` is wired to `RecordingHandler`, a mock destination that **records every request it receives**;
  every rejection test asserts `Upstream.Count == 0`, i.e. the destination never saw the request. A status code alone is
  never accepted as proof.
* **Unit tests** (`tests/SecureProxy.Tests/Unit`) cover the URL builder (traversal matrix), parameter validator, header
  policy, AES-GCM decryptor, secret source and circuit breaker.

### Traceability of the required test cases

| # | Requirement | Test(s) |
| --- | --- | --- |
| 1 | valid configured operation is forwarded | `ForwardingTests.Valid_configured_operation_is_forwarded_to_the_configured_destination`, `Post_operation_sends_validated_body_parameters_and_idempotency_key` |
| 2 | unknown operation rejected | `RejectionTests.Unknown_operation_is_rejected_and_not_forwarded` |
| 3 | disabled operation rejected | `RejectionTests.Disabled_operation_is_rejected_and_not_forwarded` |
| 4 | disabled destination rejected | `RejectionTests.Disabled_destination_is_rejected_and_not_forwarded` |
| 5 | caller-supplied destination URL cannot override configuration | `RejectionTests.Caller_supplied_routing_information_cannot_override_configuration` (5 variants), `UrlId_that_does_not_match_the_configured_destination_is_rejected` |
| 6 | invalid / disallowed HTTP method rejected | `RejectionTests.Wrong_http_method_on_the_proxy_endpoint_is_rejected`, `Operation_configured_with_a_disallowed_http_method_is_rejected_as_invalid_configuration` |
| 7 | missing required parameters rejected | `RejectionTests.Missing_required_parameters_are_rejected` |
| 8 | unknown parameters handled per operation policy | `RejectionTests.Unknown_parameters_are_rejected_when_the_operation_does_not_allow_them`, `ForwardingTests.Unknown_parameters_are_forwarded_when_the_operation_explicitly_allows_them` |
| 9 | path traversal rejected | `RejectionTests.Path_traversal_attempts_are_rejected` (10 variants), `Unit.UpstreamUriBuilderTests` |
| 10 | disallowed headers not forwarded | `ForwardingTests.Disallowed_headers_are_not_forwarded_even_when_present_on_the_request`, `Upstream_response_headers_are_relayed_only_when_allow_listed`, `Unit.HeaderPolicyTests` |
| 11 | invalid AES-GCM authentication tag rejected | `EncryptionTests.Invalid_authentication_tag_is_rejected_and_never_forwarded` |
| 12 | invalid encrypted payloads never forwarded | `EncryptionTests.*` (tampered ciphertext, wrong key, wrong operation, wrong key version, malformed structure, non-object plaintext) |
| 13 | upstream timeout handled | `ReliabilityTests.Upstream_timeout_returns_504_and_is_audited_as_timeout` |
| 14 | upstream HTTP error responses handled | `ReliabilityTests.Upstream_http_error_responses_are_relayed_with_their_status_and_marked_as_upstream` |
| 15 | cancellation propagated | `ReliabilityTests.Caller_cancellation_is_propagated_to_the_upstream_and_distinguished_from_a_timeout` |
| 16 | configuration concurrency conflicts handled | `AdminConcurrencyTests.Update_with_a_stale_concurrency_stamp_is_rejected_with_409` (HTTP 409), `Second_writer_with_the_same_stamp_is_rejected_after_the_first_commits` (service), `Concurrent_writers_racing_on_the_same_row_conflict_at_the_database` (EF Core concurrency token enforced by the database), `If_match_header_is_accepted_and_a_missing_stamp_is_rejected` |
| 17 | audit records for successful and rejected requests per policy | `ForwardingTests.Successful_forward_creates_an_audit_record_with_metadata_only`, `RejectionTests.Rejected_request_is_audited_as_rejected_and_not_forwarded`, `AuditPolicyTests.*`, `BufferedAuditPolicyTests.*` |

## 6. API contract

### `POST /api/proxy/execute`

Request (`Content-Type: application/json`, max `Proxy:MaxEnvelopeBytes`):

```json
{
  "clientId": "customer.get",                 // operation key (required)
  "json": {                                   // operation parameters (plaintext operations)
    "urlId": "crm-core",                      // REQUIRED: must equal the key of the destination bound to the operation
    "customerId": "42",
    "include": "orders"
  },
  "idempotencyKey": "order-7781"              // optional; forwarded as Idempotency-Key when the operation supports it
}
```

Operations with `RequiresEncryption = true` take `encryptedJson` instead of `json`
(AES-256-GCM, 12-byte nonce, 16-byte tag, the operation key as additional authenticated data, all base64):

```json
{ "clientId": "order.secure", "encryptedJson": { "nonce": "…", "ciphertext": "…", "tag": "…", "keyVersion": 1 } }
```

`keyVersion` is mandatory and must equal the profile's current version, so payloads encrypted with a rotated-out key are rejected rather than silently accepted.

Rules:

* Any other top-level member (`url`, `method`, `path`, `destinationUrl`, …) is rejected with `400 envelope.unknown_member`.
* `urlId` is a **consistency assertion**, never routing input: a mismatch is rejected; it is never used to build a URL.
* Parameters are validated against the operation's `ParameterRule`s and placed in the path / query string / body
  according to configuration. Unknown parameters are rejected unless `AllowUnknownParameters` is set for the operation.
* The response is the upstream response (status preserved, allow-listed headers only) with `X-Proxy-Source: upstream`,
  or a proxy error (`application/problem+json`, `X-Proxy-Source: proxy`).
* `X-Correlation-ID` is accepted (safe characters, ≤64) or generated, echoed on the response and forwarded upstream.

### Error responses

All proxy generated errors share one shape (RFC 7807) and never contain upstream host names, configuration values, stack
traces or cryptographic detail:

```json
{ "type": "https://secureproxy.example/errors/operation.unknown", "title": "The requested operation is not configured.",
  "status": 404, "code": "operation.unknown", "correlationId": "…", "source": "proxy" }
```

| Status | `code` | When |
| --- | --- | --- |
| 415 | `request.unsupported_media_type` | content type is not `application/json` |
| 413 | `request.too_large` | envelope exceeds `Proxy:MaxEnvelopeBytes` |
| 400 | `envelope.invalid_json`, `envelope.invalid`, `envelope.unknown_member`, `envelope.url_id_mismatch` | malformed or non-conforming envelope |
| 404 | `operation.unknown` | `clientId` is not a configured operation |
| 403 | `operation.disabled` | operation exists but is disabled |
| 503 | `destination.unavailable` | destination missing or disabled |
| 500 | `configuration.invalid` | operation configuration is unusable (method, template, credentials); details only in the log |
| 503 | `configuration.unavailable` | the configuration database cannot be reached and the operation is not cached (fail closed) |
| 400 | `payload.encryption_required`, `payload.encryption_not_expected`, `payload.invalid_encrypted_payload` | encryption policy / decryption failure (one generic code for every cryptographic failure) |
| 400 | `parameters.invalid` (+ `errors[]`) | parameter rules violated, including path traversal attempts |
| 413 | `request.body_too_large` | upstream body exceeds the operation's `MaxRequestBytes` |
| 429 | `request.rate_limited` | per-client rate limit (proxy endpoint: `RateLimitPermitLimit`/window; admin endpoints: `AdminRateLimitPermitPerMinute`) |
| 503 | `proxy.overloaded`, `upstream.circuit_open`, `audit.unavailable` | bounded concurrency exhausted / circuit open / mandatory audit impossible |
| 504 | `upstream.timeout` | upstream exceeded the configured timeout |
| 502 | `upstream.unreachable`, `upstream.response_too_large` | connection failure / response cap exceeded |
| 500 | `proxy.internal_error` | unexpected failure |

Upstream HTTP errors (4xx/5xx from the destination) are **relayed as-is** with `X-Proxy-Source: upstream` so callers can
tell them apart from proxy failures.

### Admin API (`/api/admin/*`, header `X-Admin-ApiKey`)

| Method & path | Purpose |
| --- | --- |
| `GET /api/admin/operations`, `GET /api/admin/operations/{key}` | list / read (response carries `ETag` = concurrency stamp) |
| `PUT /api/admin/operations/{key}` | partial update (`isEnabled`, `httpMethod`, `pathTemplate`, limits, `requiresEncryption`, …); requires `If-Match` or `concurrencyStamp`; stale → `409` with current stamp |
| `GET /api/admin/destinations`, `GET /api/admin/destinations/{key}`, `PUT /api/admin/destinations/{key}` | same for destinations |
| `GET /api/admin/configuration-changes?entityType=&entityKey=&take=` | append-only change history (field-level diff, no secrets) |

## 7. Reproducibility checklist

1. `git clone … && cd EnterpriseSecureProxy`
2. `dotnet test` → all tests green (no external dependencies).
3. `docker compose up -d` (or point `ConnectionStrings:ProxyDb` at an existing SQL Server).
4. `dotnet run --project src/SecureProxy.Api` → migrations applied, demo configuration seeded, `GET /health` → `Healthy`.
5. Send the requests from `SecureProxy.Api.http`.
