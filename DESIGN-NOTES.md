# Design Notes - Enterprise Secure Proxy Web API

## 1. Goals and guiding principles

1. **Configuration-driven.** Everything that decides *where* and *how* a request is forwarded (destination, method, path,
   headers, limits, encryption, timeouts) lives in SQL Server and is administered through a controlled API. The caller
   contributes only an operation key and validated parameters.
2. **Fail closed.** Every check that cannot be completed - unknown key, disabled row, malformed payload, missing secret,
   unusable configuration, audit store down under the mandatory policy - ends the request *before* anything is sent upstream.
3. **Defence in depth.** The envelope rejects unknown members; `urlId` must match the configured destination; path values
   are constrained *and* the final URL is re-validated against the base URL; headers are deny-by-default; secrets never
   enter the database or the logs.
4. **Explainable.** The whole flow of a request is one linear method (`ProxyExecutor.ExecuteCoreAsync`) with numbered
   steps, so it can be traced in a code review or an interview without jumping between abstractions.

## 2. Architecture and request flow

```
caller ──POST /api/proxy/execute──► CorrelationIdMiddleware ─► RateLimiter ─► ProxyController ─► ProxyExecutor
                                                                                                   │
   1 EnvelopeReader      bounded read (MaxEnvelopeBytes), strict JSON envelope, unknown members rejected
   2 OperationCatalog    clientId → Operation (+ Destination, rules, encryption profile), cached
   3 enabled?            operation enabled, destination present and enabled
   4 method              configured method must be in Proxy:AllowedHttpMethods (guards against corrupted rows)
   5 payload             plaintext json  -or-  AES-256-GCM encryptedJson (IPayloadDecryptor + ISecretSource)
   6 urlId               json.urlId must equal Destination.Key (consistency assertion, never routing input)
   7 ParameterValidator  required / type / length / range / pattern / allowed values / unknown-parameter policy
   8 UpstreamUriBuilder  BaseUrl + PathTemplate + encoded values, traversal and host-escape checks
   9 body + size         JSON body from body-located parameters, Operation.MaxRequestBytes
  10 circuit breaker     per destination, transport failures only
  11 headers/auth        HeaderPolicy allow-list, correlation id, proxy credentials from ISecretSource
  12 concurrency slot    bounded in-flight forwards (503 when saturated)
  13 audit begin         Mandatory policy: durable "Forwarding" row written here (503 + no forward if impossible)
  14 UpstreamClient      IHttpClientFactory client, linked CTS (caller cancel vs timeout), conservative retry
  15 relay               status preserved, allow-listed headers, body streamed with a byte cap
  16 audit complete      row updated (Mandatory) or queued (Buffered)
```

Components are small classes behind interfaces (`IEnvelopeReader`, `IOperationCatalog`, `IPayloadDecryptor`,
`IParameterValidator`, `IUpstreamClient`, `IDestinationCircuitBreaker`, `IAuditRecorder`, `ISecretSource`) so each can be
unit-tested or replaced (e.g. Polly for the breaker, Key Vault for secrets) without touching the executor.

## 3. Interpreting the request contract (`clientId`, `json`, `urlId`)

The assessment's example request is partially garbled, so the following interpretation is implemented and documented:

| Member | Meaning in this implementation |
| --- | --- |
| `clientId` | the **operation key** (`customer.get`) - "find the operation using its clientId key" |
| `json` | the operation parameters object |
| `json.urlId` | **required**; must equal the key of the destination the operation is bound to. It is treated as a *consistency assertion* (the caller states which upstream it believes it is talking to); a mismatch is rejected (`envelope.url_id_mismatch`) and the value is never used to pick or build a URL - "the caller does not choose the destination URL" |
| `encryptedJson` | replaces `json` for operations with `RequiresEncryption` |
| `idempotencyKey` | optional caller-supplied idempotency key (see §7.4) |

The envelope is deliberately closed: any other member is rejected, which is what makes "a caller-supplied destination URL
cannot override configuration" true by construction rather than by a blacklist.

## 4. Security decisions

### 4.1 No caller-controlled routing
* Destination URL, method and path template come from `Destinations` / `Operations` rows only.
* Unknown envelope members → 400. `urlId` mismatch → 400.
* The configured method itself is validated against an allow-list at execution time, so a corrupted or malicious row
  cannot turn the proxy into a `TRACE`/`CONNECT` relay.

### 4.2 Path traversal and URL smuggling (`UpstreamUriBuilder`)
* Placeholders must occupy a whole path segment; templates with `.`/`..`/empty segments, `://`, `?`, `#`, `\` are invalid configuration.
* Path values are restricted to a conservative character set (letters, digits, `-_.~@:+=, ` and space) and may never be
  `.`/`..` or contain `..`. Slashes, backslashes and `%` are rejected outright, so an upstream that decodes `%2F`/`%2E`
  cannot be tricked by double encoding.
* After construction the absolute URL must have the same scheme, host and port as the base URL, must start with the base
  path, must not contain dot segments and must not carry user-info. Allowed schemes (`https` only in production) and an
  optional per-destination port allow-list are enforced as well.

### 4.3 Headers (`HeaderPolicy`)
* Request headers are **deny-by-default**: only names allow-listed for the operation are copied, and a hard "never"
  list (hop-by-hop, `Authorization`, `Cookie`, `Host`, `X-Forwarded-*`, `Content-Length`, …) wins over any allow-list.
  The proxy authenticates to upstreams with *its own* credentials (`Destination.AuthType` + secret reference).
* Response headers: a small default allow-list (`Content-Type`, `Cache-Control`, `ETag`, …) plus per-operation entries;
  `Set-Cookie`, `Server`, `Location` (internal host names), `WWW-Authenticate` etc. are never relayed.
* Header values are checked for CR/LF/control characters before being added.

### 4.4 Payload encryption (AES-256-GCM)
* `EncryptionProfile` stores algorithm, key *reference*, key version and enabled flag - **never key material**.
* `ISecretSource` is the key source abstraction. `ConfigurationSecretSource` resolves `cfg:<name>` from the `Secrets`
  configuration section, which locally comes from user-secrets/environment and in production from a secret-manager
  configuration provider (Key Vault, AWS Secrets Manager, …) without code changes.
* The operation key is bound as **additional authenticated data**, so a ciphertext captured for `order.create` cannot be
  replayed against `order.secure`. `keyVersion` is mandatory and must match the profile, which enables key rotation
  (publish the new key under a new profile version; payloads carrying the old version are rejected, never silently accepted).
  Secret values are read from the source on every use (no process-lifetime cache), so rotating the value behind a
  reference takes effect without a restart. Decrypted plaintext is zeroed once the request has been processed.
* Every failure category (bad base64, wrong nonce/tag length, wrong key, tag mismatch, plaintext not a JSON object) maps
  to the same generic `400 payload.invalid_encrypted_payload`; the category is logged internally only.
* Decrypted parameters go through the same `ParameterValidator` as plaintext ones.

### 4.5 Secrets and logs
* Secrets exist only in the secret source; the database holds references, admin responses show references, audit rows
  and logs hold metadata only (`AuditPolicyTests.Audit_records_never_contain_headers_bodies_or_secrets`).
* Public error bodies never contain upstream hosts, configuration values, exception text or cryptographic detail.

### 4.6 Admin API
Protected by a constant-time compared API key header; **disabled (404) when no key is configured**. It is intentionally
the single seam to replace with OAuth2/mTLS. Every change is validated (method allow-list, template probe through the same
URL builder, limits) and recorded in `ConfigurationChanges` with a field-level diff.

## 5. Data model

| Table | Purpose / notable columns |
| --- | --- |
| `Destinations` | `Key` (unique, = `urlId`), `BaseUrl`, `IsEnabled`, `TimeoutSeconds`, `AllowedPorts`, `AuthType/AuthHeaderName/AuthSecretReference`, timestamps, `ConcurrencyStamp` |
| `Operations` | `Key` (unique), `DestinationId`, `HttpMethod`, `PathTemplate`, `IsEnabled`, `MaxRequestBytes`, `MaxResponseBytes`, `TimeoutSeconds`, `RequiresEncryption`, `EncryptionProfileId`, `AllowUnknownParameters`, `SupportsIdempotencyKey`, timestamps, `ConcurrencyStamp` |
| `ParameterRules` | per operation: `Name`, `Location` (Path/Query/Body), `IsRequired`, `DataType`, `MaxLength`, `MinValue/MaxValue`, `Pattern`, `AllowedValues`; unique `(OperationId, Name)` |
| `HeaderRules` | per operation allow-list entries, `Direction` Request/Response; unique `(OperationId, HeaderName, Direction)` |
| `EncryptionProfiles` | `Key`, `Algorithm`, `KeyReference`, `KeyVersion`, `IsEnabled` |
| `RequestLogs` | audit: correlation id, operation/destination keys and ids, method, start/complete/duration, `Forwarded`, upstream status, proxy status, `Outcome`, `ReasonCode`, `ReasonDetail`, client address, byte counts; indexed on correlation id, start time, `(OperationKey, StartedAtUtc)` |
| `ConfigurationChanges` | append-only history: entity type/id/key, action, `ChangedBy`, timestamp, correlation id, `ChangesJson` diff |

Enums are stored as strings for readability in SQL; timestamps are UTC `datetime2`. The schema is created by the EF Core
migration `20261108181619_InitialCreate` (`scripts/schema.sql` is the generated idempotent equivalent).

**Configuration history scope.** `ConfigurationChanges` records every change made through the admin API (currently
operation and destination updates; the `Created`/`Deleted` actions are reserved for the create/delete endpoints that would
complete the admin surface). Changes made directly in SQL - including to parameter rules, header rules and encryption
profiles, which have no admin endpoint yet - are **not** captured; a deployment that needs that guarantee should enable
SQL Server temporal tables (`SYSTEM_VERSIONING`) on the configuration tables, which complements this application-level
history without application changes.

## 6. Configuration caching and consistency model

* If the configuration database cannot be reached and the key is not cached, the request is rejected with
  `503 configuration.unavailable` (fail closed); cached operations keep working for the remainder of their TTL, which is
  the proxy's tolerance window for a short database outage.
* `OperationCatalog` caches a **`ResolvedOperation` snapshot** (operation + destination + rules + profile) in
  `IMemoryCache` for `Proxy:ConfigCacheSeconds` (default 30 s). Misses are cached for `NegativeCacheSeconds` (5 s) so
  unknown keys cannot be used to hammer SQL Server.
* **Invalidation:** the admin API invalidates the affected key (operation change) or the whole cache via a generation
  counter (destination change) on the instance that performed the change → effective immediately there. A load that was
  already in progress when the invalidation happened is served once but **not cached** (per-key epoch and global generation
  are re-checked before writing to the cache), so a concurrent request cannot resurrect the stale configuration.
* **Other instances** see the change when their TTL expires → *eventual consistency bounded by the TTL*. Documented
  consequence: after disabling an operation, a request may still be accepted for up to 30 s on another instance. For a
  tighter bound, lower the TTL or add a shared invalidation channel (SQL Server `SqlDependency`, Redis pub/sub, or a
  `ConfigurationVersion` row polled every few seconds) behind the same `IOperationCatalog` interface.
* **Requests already executing** when an operation/destination is disabled complete with the snapshot they started with;
  they are never aborted mid-flight (aborting could leave the upstream in a half-applied state). New requests are rejected
  immediately on the admin instance and within the TTL elsewhere
  (`AdminConcurrencyTests.Requests_already_executing_complete_with_the_configuration_they_started_with`).

## 7. Concurrency, reliability and performance

### 7.1 Configuration concurrency
Each configuration row carries a `ConcurrencyStamp` (GUID, EF Core `IsConcurrencyToken`), regenerated on every update
and exposed as an `ETag`. Updates must supply the current stamp (`If-Match` or body). Two layers handle stale updates:
1. an explicit comparison → deterministic `409 Conflict` carrying the current stamp;
2. the database `UPDATE … WHERE ConcurrencyStamp = @original` → `DbUpdateConcurrencyException` → `409` for true races.

*Why a GUID stamp instead of SQL Server `rowversion`?* Identical semantics and HTTP behaviour, but provider-neutral: the
tests run the exact same code on SQLite, and ETags are plain strings. Switching to `rowversion` is a one-line mapping change
(`IsRowVersion()` on a `byte[]`) if a DBA prefers it.

### 7.2 Timeouts and cancellation
* Effective timeout = `Operation.TimeoutSeconds ?? Destination.TimeoutSeconds`, clamped to `Proxy:MaxTimeoutSeconds`.
* `UpstreamClient` links `HttpContext.RequestAborted` with a `CancelAfter(timeout)` source. When an
  `OperationCanceledException` surfaces: caller token cancelled → **caller cancellation** (audited as `CallerCancelled`,
  status 499 in the log, nothing written to a client that is gone); otherwise → **upstream timeout** → `504 upstream.timeout`.
* The linked token is also used while streaming the response body, so a slow body cannot outlive the timeout.
* The `HttpClient.Timeout` is disabled (`InfiniteTimeSpan`) so there is exactly one timeout authority.

### 7.3 HttpClient lifecycle
One named client (`"upstream"`) from `IHttpClientFactory` over a `SocketsHttpHandler` with pooled connections
(`PooledConnectionLifetime` 5 min for DNS freshness), `AllowAutoRedirect = false` (a redirect could point outside the
configured destination), `UseCookies = false`, bounded response header size, and infinite handler lifetime (the handler
already recycles connections). No `HttpClient` is created per request.

### 7.4 Retries and idempotency
* The proxy **never retries non-idempotent operations**. The only automatic retry is: safe methods (GET/HEAD/OPTIONS)
  after a *connection-level* failure (`HttpRequestError.ConnectionError/NameResolutionError/SecureConnectionError`), exactly
  once, immediately - the request provably never reached the server. Timeouts are never retried (the request may be executing).
* **Safe to retry:** DNS/connect/TLS handshake failures for safe methods. **Not safe:** anything after the request was sent
  (timeouts, resets, 5xx) for POST/PUT/PATCH/DELETE.
* **Duplicate prevention for POST:** operations with `SupportsIdempotencyKey` forward the caller's `idempotencyKey` as the
  `Idempotency-Key` header. The key is caller-generated (so the *caller's* retries carry the same key) and the proxy reuses
  it unchanged, letting an upstream that implements idempotency keys / deduplication collapse duplicates. The proxy itself
  deliberately does not de-duplicate: it has no durable knowledge of whether a previous attempt reached the upstream, so a
  proxy-side cache could only hide a real second order or block a legitimate one.
* The circuit breaker and the concurrency limiter reject *before* sending, so they can never cause duplicates.

### 7.5 Streaming and size limits
* The envelope is read through a hard byte cap (`Proxy:MaxEnvelopeBytes`, also applied to Kestrel's request body limit);
  it must be fully parsed because parameters are validated as a whole.
* The upstream body is built from validated parameters and checked against `Operation.MaxRequestBytes`.
* The response is **streamed** (`HttpCompletionOption.ResponseHeadersRead`) with 64 KB buffers. A declared `Content-Length`
  above the cap → `502 upstream.response_too_large` before anything is written; an undeclared body that grows past the cap →
  `502` if headers have not been sent yet, otherwise the connection is aborted (the only honest option once bytes are on
  the wire). Both outcomes are audited as `ResponseTooLarge`.

### 7.6 Rate limiting, bounded concurrency, circuit breaking
* **Rate limiting:** ASP.NET Core `RateLimiter` middleware, fixed window per client address (`Resilience:RateLimit*`),
  `429` with `Retry-After`, problem+json body, nothing forwarded.
* **Bounded concurrency:** `ForwardingConcurrencyLimiter` (semaphore, `MaxConcurrentForwards`); when saturated the request
  fails fast with `503 proxy.overloaded` instead of queueing indefinitely.
* **Circuit breaker:** per destination, counts *consecutive transport failures* (timeouts, connection errors - not HTTP
  error responses, which are legitimate answers). After `FailureThreshold` it opens for `BreakSeconds`
  (`503 upstream.circuit_open`, not forwarded), then lets a single probe through (half-open). The executor holds the probe
  as a lease: every exit path reports success, failure or *release* (caller cancelled, no slot, audit unavailable), and a
  probe that is never reported back expires after the break period, so the circuit can never latch open. Dependency free;
  Polly / `Microsoft.Extensions.Http.Resilience` would plug into the same interface in production.

## 8. Audit policy, logging and observability

### 8.1 Audit persistence policy (configurable, defaults chosen deliberately)
| Event | Default policy | Behaviour when SQL Server is unavailable |
| --- | --- | --- |
| Forwarded execution | **Mandatory** | A `Forwarding` row is written synchronously *before* the upstream call. If the write fails the request is rejected with `503 audit.unavailable` and **not forwarded** (fail closed - no un-audited side effects). After the call the same row is updated with the outcome; if that update fails the attempt is still provably recorded. |
| Rejected request | **Buffered** | Queued in a bounded in-memory channel (`BufferCapacity`, default 10 000) and written in batches by `BufferedAuditWriter` every `FlushIntervalMilliseconds`. Nothing reached an upstream, so availability wins: the caller still gets its 4xx. When the buffer is full, records are dropped and counted (`DroppedCount`, error log). |

`Audit:ForwardingPolicy=Buffered` trades durability for availability (requests keep flowing during an outage, records are
written when the database returns, with a bounded loss window) - `BufferedAuditPolicyTests` demonstrates it.
Operational consequences: the mandatory default adds two short SQL writes to every forwarded request and makes SQL Server
availability a hard dependency for forwarding; the buffered mode removes that dependency but can lose up to
`BufferCapacity` records per instance on a crash.

### 8.2 What is recorded
Correlation id, operation and destination keys/ids, method, start/completion timestamps, duration, `Forwarded`, upstream
status, proxy status, outcome category, reason code and a short non-sensitive reason, client address, byte counts.
**Never:** headers, bodies, credentials, key material, decrypted content, or caller-supplied text (the public error
message may list unknown envelope member names to help the caller; the audit row stores a fixed description instead).
Auditing is a single step in `ProxyExecutor.ExecuteAsync`'s `finally` block, so every path - rejection, forward, upstream
failure, caller disconnect, unexpected exception - produces exactly one final record (or completes the pre-written one).

### 8.3 Structured logging
`ILogger` with source-generated messages (`ProxyLog`), a `CorrelationId` scope on every line, JSON console output outside
Development. Logs contain the same metadata as the audit plus internal diagnostics (e.g. *which* configuration problem,
*which* decryption failure category) that are intentionally kept out of public responses. Exceptions from upstream
transport failures are logged with their type/`HttpRequestError`.

## 9. Error handling and HTTP semantics
* Proxy failures: uniform `application/problem+json` with a stable `code`, the correlation id and `X-Proxy-Source: proxy`.
* Upstream responses: status preserved, allow-listed headers, `X-Proxy-Source: upstream`, so a `404` from the upstream is
  distinguishable from the proxy's own `404 operation.unknown`.
* Mapping: unknown operation 404 · disabled operation 403 · destination unavailable 503 · configuration store unreachable 503 · invalid configuration 500 ·
  invalid envelope/parameters/encryption 400 · media type 415 · sizes 413 · rate limit 429 · overload/circuit/audit 503 ·
  timeout 504 · unreachable/oversized response 502 · concurrency conflict 409 (admin).
* A global exception handler covers anything outside the executor (admin API) with the same non-sensitive body.

## 10. Testing strategy
* `WebApplicationFactory<Program>` boots the production pipeline; only three things are substituted: SQL Server → a private
  SQLite file (a real relational provider, so concurrency tokens, unique indexes and query translation are exercised),
  the upstream `HttpClient` → `RecordingHandler`, and secrets/admin key → in-memory configuration.
* `RecordingHandler` is the mock destination required by the assessment: it records every request (method, URL, headers,
  body, whether the proxy cancelled it) and answers with scripted responses (delays, failures, status codes, oversized or
  chunked bodies). Every rejection test asserts the destination received **zero** requests.
* `FailingSaveChangesInterceptor` simulates "SQL Server unavailable" for writes only, to test both audit policies.
* Unit tests cover the pure components (URL builder, parameter validator, header policy, AES-GCM, secret source, breaker).

## 11. Trade-offs, limitations and next steps
* **Admin authentication** is an API key by design for the assessment (constant-time compared, rate limited per client, disabled when unset); production should use OAuth2 client credentials or mTLS (single filter to replace).
* **Admin surface** covers reading and updating operations/destinations and reading history; create/delete endpoints and rule/profile administration are the natural next step (the change-history model already has the actions).
* **Cross-instance cache invalidation** is TTL based (see §6); a pub/sub channel would tighten the bound.
* **Response encryption** is not implemented (not required); the `EncryptionProfile` model and `ISecretSource` already support adding it.
* **Audit retention / partitioning** of `RequestLogs` is an operational concern (time-based partitioning or a retention job).
* **Mandatory audit = two writes per forward.** Acceptable for an enterprise proxy with compliance needs; switchable per deployment.
* **Rate limiting by client address** is a baseline; with authenticated callers the partition key should become the client identity.
* **Polly** was intentionally not added so the resilience behaviour is fully visible in ~100 lines of code; the seams exist to swap it in.
