using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Audit;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Infrastructure;
using SecureProxy.Api.Security;

namespace SecureProxy.Api.Proxy;

/// <summary>
/// Orchestrates one <c>POST /api/proxy/execute</c> call. The sequence is strictly ordered and <b>fail closed</b>:
/// envelope → operation → destination → method → payload (decrypt) → urlId → parameters → URL → body size →
/// circuit breaker → headers/auth → concurrency slot → audit (mandatory) → forward → relay → audit (complete).
/// A request that fails any step before "forward" never reaches the upstream.
/// </summary>
public sealed class ProxyExecutor
{
    private static readonly string[] SafeMethods = ["GET", "HEAD", "OPTIONS"];
    private static readonly string[] BodyMethods = ["POST", "PUT", "PATCH"];
    private static readonly MediaTypeHeaderValue JsonMediaType = new("application/json") { CharSet = "utf-8" };

    private readonly IEnvelopeReader _envelopeReader;
    private readonly IOperationCatalog _catalog;
    private readonly IPayloadDecryptor _decryptor;
    private readonly IParameterValidator _parameterValidator;
    private readonly IUpstreamClient _upstream;
    private readonly IDestinationCircuitBreaker _circuitBreaker;
    private readonly ForwardingConcurrencyLimiter _concurrency;
    private readonly ISecretSource _secrets;
    private readonly IAuditRecorder _audit;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly TimeProvider _time;
    private readonly ILogger<ProxyExecutor> _logger;

    public ProxyExecutor(
        IEnvelopeReader envelopeReader,
        IOperationCatalog catalog,
        IPayloadDecryptor decryptor,
        IParameterValidator parameterValidator,
        IUpstreamClient upstream,
        IDestinationCircuitBreaker circuitBreaker,
        ForwardingConcurrencyLimiter concurrency,
        ISecretSource secrets,
        IAuditRecorder audit,
        IOptionsMonitor<ProxyOptions> options,
        TimeProvider time,
        ILogger<ProxyExecutor> logger)
    {
        _envelopeReader = envelopeReader;
        _catalog = catalog;
        _decryptor = decryptor;
        _parameterValidator = parameterValidator;
        _upstream = upstream;
        _circuitBreaker = circuitBreaker;
        _concurrency = concurrency;
        _secrets = secrets;
        _audit = audit;
        _options = options;
        _time = time;
        _logger = logger;
    }

    public async Task ExecuteAsync(HttpContext context)
    {
        var correlationId = CorrelationIdMiddleware.Get(context);
        var startedTimestamp = Stopwatch.GetTimestamp();
        var log = new RequestLog
        {
            CorrelationId = correlationId,
            StartedAtUtc = _time.GetUtcNow().UtcDateTime,
            ClientAddress = context.Connection.RemoteIpAddress?.ToString()
        };

        var state = new ExecutionState();
        try
        {
            await ExecuteCoreAsync(context, log, correlationId, startedTimestamp, state).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The caller went away. Keep an outcome that was already decided (e.g. a rejection whose response could not be
            // written); otherwise record the cancellation itself.
            if (log.CompletedAtUtc is null)
            {
                Complete(log, startedTimestamp, RequestOutcome.CallerCancelled, 499, null, "Caller cancelled the request.");
            }

            ProxyLog.CallerCancelled(_logger, log.OperationKey, log.DurationMs ?? 0, log.Forwarded);
        }
        catch (Exception ex)
        {
            ProxyLog.UnhandledError(_logger, ex, log.OperationKey, log.Forwarded);
            Complete(log, startedTimestamp, RequestOutcome.ProxyError, StatusCodes.Status500InternalServerError, ProxyErrorCodes.InternalError, "Unexpected proxy error.");
            try
            {
                if (!context.Response.HasStarted)
                {
                    await context.WriteProblemAsync(new ProxyRejection(StatusCodes.Status500InternalServerError, ProxyErrorCodes.InternalError, "The proxy could not process the request."), correlationId).ConfigureAwait(false);
                }
                else
                {
                    context.Abort();
                }
            }
            catch (Exception writeFailure) when (writeFailure is OperationCanceledException or IOException)
            {
                // Client is gone; nothing left to tell it. The audit below still happens.
            }
        }
        finally
        {
            // Single audit point for every path: forwarded requests complete the record opened before the upstream call,
            // everything else (rejections, proxy errors, early cancellations) is recorded as a non-forwarded attempt.
            if (state.Ticket is { } ticket)
            {
                await _audit.CompleteForwardingAsync(ticket, log).ConfigureAwait(false);
            }
            else
            {
                await _audit.RecordRejectionAsync(log).ConfigureAwait(false);
            }
        }
    }

    private sealed class ExecutionState
    {
        /// <summary>Set as soon as the audit "begin" step succeeded, so every exit path completes the same record.</summary>
        public AuditTicket? Ticket;
    }

    /// <summary>Runs the pipeline. Every early return is a rejection whose response has already been written; auditing is centralised in <see cref="ExecuteAsync"/>.</summary>
    private async Task ExecuteCoreAsync(HttpContext context, RequestLog log, string correlationId, long startedTimestamp, ExecutionState state)
    {
        var cancellationToken = context.RequestAborted;
        var options = _options.CurrentValue;

        // 1. Envelope -------------------------------------------------------------------------------------------
        var read = await _envelopeReader.ReadAsync(context.Request, cancellationToken).ConfigureAwait(false);
        log.RequestBytes = read.BytesRead;
        if (!read.Succeeded)
        {
            await RejectAsync(context, log, startedTimestamp, read.Rejection!, correlationId).ConfigureAwait(false);
            return;
        }

        using var envelope = read.Envelope!;
        log.OperationKey = envelope.ClientId;

        // 2. Operation ------------------------------------------------------------------------------------------
        ResolvedOperation? resolved;
        try
        {
            resolved = await _catalog.ResolveAsync(envelope.ClientId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The configuration store is unreachable and the operation is not cached: fail closed with an honest status.
            _logger.LogError(ex, "Configuration store unavailable while resolving operation {OperationKey}", envelope.ClientId);
            await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status503ServiceUnavailable, ProxyErrorCodes.ConfigurationUnavailable, "The proxy configuration is temporarily unavailable."), correlationId).ConfigureAwait(false);
            return;
        }

        if (resolved is null)
        {
            await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status404NotFound, ProxyErrorCodes.UnknownOperation, "The requested operation is not configured."), correlationId).ConfigureAwait(false);
            return;
        }

        var operation = resolved.Operation;
        var destination = resolved.Destination;
        log.OperationId = operation.Id;
        log.DestinationId = destination?.Id;
        log.DestinationKey = destination?.Key;
        log.HttpMethod = operation.HttpMethod;

        if (!operation.IsEnabled)
        {
            await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status403Forbidden, ProxyErrorCodes.OperationDisabled, "The requested operation is disabled."), correlationId).ConfigureAwait(false);
            return;
        }

        // 3. Destination ----------------------------------------------------------------------------------------
        if (destination is null || !destination.IsEnabled)
        {
            await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status503ServiceUnavailable, ProxyErrorCodes.DestinationUnavailable, "The destination for this operation is not available."), correlationId).ConfigureAwait(false);
            return;
        }

        // 4. Method (trusted configuration, but still validated so a corrupted row cannot turn the proxy into something else)
        var method = operation.HttpMethod.ToUpperInvariant();
        if (!options.AllowedHttpMethods.Contains(method, StringComparer.Ordinal))
        {
            await RejectConfigurationAsync(context, log, startedTimestamp, resolved, $"HTTP method '{operation.HttpMethod}' is not permitted.", correlationId).ConfigureAwait(false);
            return;
        }

        // 5. Payload (plaintext or AES-GCM) ---------------------------------------------------------------------
        JsonElement json;
        JsonDocument? decryptedDocument = null;
        byte[]? plaintext = null;
        try
        {
            if (operation.RequiresEncryption)
            {
                if (envelope.EncryptedJson is null)
                {
                    await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.EncryptionRequired, "This operation requires an encrypted payload ('encryptedJson')."), correlationId).ConfigureAwait(false);
                    return;
                }

                if (resolved.EncryptionProfile is null)
                {
                    await RejectConfigurationAsync(context, log, startedTimestamp, resolved, "Operation requires encryption but has no encryption profile.", correlationId).ConfigureAwait(false);
                    return;
                }

                var decryption = await _decryptor.DecryptAsync(resolved.EncryptionProfile, operation.Key, envelope.EncryptedJson, cancellationToken).ConfigureAwait(false);
                plaintext = decryption.Plaintext;
                if (!decryption.Succeeded || !TryParseObject(plaintext!, out decryptedDocument))
                {
                    ProxyLog.DecryptionFailed(_logger, operation.Key, decryption.Succeeded ? "PlaintextNotJsonObject" : decryption.Failure.ToString());
                    await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.DecryptionFailed, "The encrypted payload could not be accepted."), correlationId).ConfigureAwait(false);
                    return;
                }

                json = decryptedDocument!.RootElement;
            }
            else
            {
                if (envelope.EncryptedJson is not null)
                {
                    await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.EncryptionNotExpected, "This operation does not accept an encrypted payload."), correlationId).ConfigureAwait(false);
                    return;
                }

                json = envelope.Json!.Value;
            }

            // 6. urlId consistency assertion -------------------------------------------------------------------
            if (!json.TryGetProperty(ProxyEnvelope.UrlIdMember, out var urlId) || urlId.ValueKind != JsonValueKind.String ||
                !string.Equals(urlId.GetString(), destination.Key, StringComparison.Ordinal))
            {
                await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.UrlIdMismatch, "'json.urlId' is required and must match the destination configured for the operation."), correlationId).ConfigureAwait(false);
                return;
            }

            // 7. Parameters -----------------------------------------------------------------------------------
            var validation = _parameterValidator.Validate(resolved, json);
            if (!validation.Succeeded)
            {
                await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidParameters, "Request parameters are invalid.", validation.Errors), correlationId).ConfigureAwait(false);
                return;
            }

            var parameters = validation.Parameters!;

            // 8. Upstream URL (trusted base + template, validated values) --------------------------------------
            var uriResult = UpstreamUriBuilder.Build(destination.BaseUrl, operation.PathTemplate, parameters.Path, parameters.Query, options.AllowedDestinationSchemes, destination.AllowedPorts);
            if (!uriResult.Succeeded)
            {
                if (uriResult.CallerFault)
                {
                    await RejectAsync(context, log, startedTimestamp, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidParameters, "Request parameters are invalid.", [new ParameterError("path", "invalid_path_value", uriResult.Error!)]), correlationId).ConfigureAwait(false);
                }
                else
                {
                    await RejectConfigurationAsync(context, log, startedTimestamp, resolved, uriResult.Error!, correlationId).ConfigureAwait(false);
                }

                return;
            }

            // 9. Body + size limit ----------------------------------------------------------------------------
            byte[]? body = null;
            if (BodyMethods.Contains(method, StringComparer.Ordinal))
            {
                body = Encoding.UTF8.GetBytes(parameters.Body?.ToJsonString() ?? "{}");
                if (body.LongLength > operation.MaxRequestBytes)
                {
                    await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status413PayloadTooLarge, ProxyErrorCodes.RequestBodyTooLarge, "The request body exceeds the limit configured for this operation."), correlationId).ConfigureAwait(false);
                    return;
                }
            }

            // 10. Circuit breaker -----------------------------------------------------------------------------
            if (!_circuitBreaker.TryEnter(destination.Id))
            {
                await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status503ServiceUnavailable, ProxyErrorCodes.CircuitOpen, "The destination is temporarily unavailable."), correlationId).ConfigureAwait(false);
                return;
            }

            // From here on the breaker must hear back exactly once (success / failure / release).
            var breakerOutcomeRecorded = false;
            try
            {
                // 11. Upstream request message (allow-listed headers, proxy credentials) -----------------------
                using var upstreamRequest = new HttpRequestMessage(new HttpMethod(method), uriResult.Uri);
                foreach (var (name, value) in HeaderPolicy.SelectRequestHeaders(context.Request.Headers, resolved.RequestHeaderAllowlist))
                {
                    upstreamRequest.Headers.TryAddWithoutValidation(name, value);
                }

                upstreamRequest.Headers.TryAddWithoutValidation(options.CorrelationHeaderName, correlationId);
                upstreamRequest.Headers.TryAddWithoutValidation("Accept", "application/json");
                upstreamRequest.Headers.TryAddWithoutValidation("User-Agent", options.UserAgent);
                if (operation.SupportsIdempotencyKey && envelope.IdempotencyKey is not null)
                {
                    upstreamRequest.Headers.TryAddWithoutValidation("Idempotency-Key", envelope.IdempotencyKey);
                }

                if (!await TryApplyUpstreamAuthenticationAsync(upstreamRequest, destination, cancellationToken).ConfigureAwait(false))
                {
                    await RejectConfigurationAsync(context, log, startedTimestamp, resolved, "Upstream credentials could not be resolved.", correlationId).ConfigureAwait(false);
                    return;
                }

                if (body is not null)
                {
                    upstreamRequest.Content = new ByteArrayContent(body);
                    upstreamRequest.Content.Headers.ContentType = JsonMediaType;
                }

                // 12. Bounded concurrency ---------------------------------------------------------------------
                using var slot = await _concurrency.TryAcquireAsync(cancellationToken).ConfigureAwait(false);
                if (slot is null)
                {
                    await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status503ServiceUnavailable, ProxyErrorCodes.Overloaded, "The proxy is temporarily overloaded."), correlationId).ConfigureAwait(false);
                    return;
                }

                // 13. Audit before forwarding (mandatory policy writes a durable row here) ---------------------
                AuditTicket ticket;
                try
                {
                    ticket = await _audit.BeginForwardingAsync(log, cancellationToken).ConfigureAwait(false);
                    state.Ticket = ticket;
                }
                catch (AuditUnavailableException)
                {
                    await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status503ServiceUnavailable, ProxyErrorCodes.AuditUnavailable, "The request cannot be audited and was not forwarded."), correlationId).ConfigureAwait(false);
                    return;
                }

                // 14. Forward ---------------------------------------------------------------------------------
                var timeout = resolved.EffectiveTimeout(options.MaxTimeoutSeconds);
                log.Forwarded = true;
                using var send = await _upstream.SendAsync(upstreamRequest, timeout, SafeMethods.Contains(method, StringComparer.Ordinal), cancellationToken).ConfigureAwait(false);

                switch (send.Failure)
                {
                    case UpstreamFailure.Timeout:
                        _circuitBreaker.RecordFailure(destination.Id);
                        breakerOutcomeRecorded = true;
                        ProxyLog.UpstreamTimeout(_logger, operation.Key, destination.Key, (long)timeout.TotalMilliseconds);
                        Complete(log, startedTimestamp, RequestOutcome.UpstreamTimeout, StatusCodes.Status504GatewayTimeout, ProxyErrorCodes.UpstreamTimeout, "Upstream did not respond within the configured timeout.");
                        await context.WriteProblemAsync(new ProxyRejection(StatusCodes.Status504GatewayTimeout, ProxyErrorCodes.UpstreamTimeout, "The upstream service did not respond in time."), correlationId).ConfigureAwait(false);
                        break;

                    case UpstreamFailure.Unreachable:
                        _circuitBreaker.RecordFailure(destination.Id);
                        breakerOutcomeRecorded = true;
                        ProxyLog.UpstreamUnreachable(_logger, operation.Key, destination.Key);
                        Complete(log, startedTimestamp, RequestOutcome.UpstreamUnreachable, StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamUnreachable, "Upstream connection failed.");
                        await context.WriteProblemAsync(new ProxyRejection(StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamUnreachable, "The upstream service could not be reached."), correlationId).ConfigureAwait(false);
                        break;

                    case UpstreamFailure.CallerCancelled:
                        // No verdict on the destination: the probe slot is released in the finally block below.
                        Complete(log, startedTimestamp, RequestOutcome.CallerCancelled, 499, null, "Caller cancelled the request.");
                        ProxyLog.CallerCancelled(_logger, operation.Key, log.DurationMs ?? 0, forwarded: true);
                        break;

                    default:
                        _circuitBreaker.RecordSuccess(destination.Id);
                        breakerOutcomeRecorded = true;
                        await RelayAsync(context, log, startedTimestamp, resolved, send, correlationId).ConfigureAwait(false);
                        break;
                }

                // 15. Audit completion happens in ExecuteAsync's finally block (same row under the mandatory policy,
                //     queued under the buffered policy) so that it also runs when relaying throws.
            }
            finally
            {
                if (!breakerOutcomeRecorded)
                {
                    _circuitBreaker.Release(destination.Id);
                }
            }
        }
        finally
        {
            decryptedDocument?.Dispose();
            if (plaintext is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private async Task RelayAsync(HttpContext context, RequestLog log, long startedTimestamp, ResolvedOperation resolved, UpstreamSendResult send, string correlationId)
    {
        var response = send.Response!;
        var options = _options.CurrentValue;
        var maxResponseBytes = resolved.Operation.MaxResponseBytes ?? options.DefaultMaxResponseBytes;
        var upstreamStatus = (int)response.StatusCode;
        log.UpstreamStatusCode = upstreamStatus;

        if (response.Content.Headers.ContentLength is { } declared && declared > maxResponseBytes)
        {
            Complete(log, startedTimestamp, RequestOutcome.ResponseTooLarge, StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamResponseTooLarge, "Upstream response exceeds the permitted size.");
            ProxyLog.ResponseTooLarge(_logger, maxResponseBytes, resolved.Key, 0);
            await context.WriteProblemAsync(new ProxyRejection(StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamResponseTooLarge, "The upstream response exceeds the permitted size."), correlationId).ConfigureAwait(false);
            return;
        }

        var httpResponse = context.Response;
        httpResponse.StatusCode = upstreamStatus;
        httpResponse.Headers[ProblemDetailsFactoryExtensions.ProxySourceHeader] = "upstream";
        foreach (var (name, values) in HeaderPolicy.SelectResponseHeaders(response, new HashSet<string>(options.DefaultResponseHeaderAllowlist, StringComparer.OrdinalIgnoreCase), resolved.ResponseHeaderAllowlist))
        {
            httpResponse.Headers[name] = values;
        }

        long relayed = 0;
        try
        {
            await using var upstreamBody = await response.Content.ReadAsStreamAsync(send.Token).ConfigureAwait(false);
            var buffer = new byte[64 * 1024];
            while (true)
            {
                var read = await upstreamBody.ReadAsync(buffer, send.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                relayed += read;
                if (relayed > maxResponseBytes)
                {
                    ProxyLog.ResponseTooLarge(_logger, maxResponseBytes, resolved.Key, relayed);
                    Complete(log, startedTimestamp, RequestOutcome.ResponseTooLarge, StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamResponseTooLarge, "Upstream response exceeded the permitted size while streaming.");
                    if (!httpResponse.HasStarted)
                    {
                        // Nothing has reached the caller yet: replace the relayed response with a proper proxy error.
                        await context.WriteProblemAsync(new ProxyRejection(StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamResponseTooLarge, "The upstream response exceeds the permitted size."), correlationId).ConfigureAwait(false);
                    }
                    else
                    {
                        // Headers and part of the body are already on the wire; the only honest option left is to drop the connection.
                        context.Abort();
                    }

                    return;
                }

                await httpResponse.Body.WriteAsync(buffer.AsMemory(0, read), send.Token).ConfigureAwait(false);
            }

            await httpResponse.Body.FlushAsync(send.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            Complete(log, startedTimestamp, RequestOutcome.CallerCancelled, 499, null, "Caller cancelled while the response was being relayed.");
            ProxyLog.CallerCancelled(_logger, resolved.Key, log.DurationMs ?? 0, forwarded: true);
            return;
        }
        catch (OperationCanceledException)
        {
            ProxyLog.UpstreamTimeout(_logger, resolved.Key, resolved.Destination.Key, (long)resolved.EffectiveTimeout(options.MaxTimeoutSeconds).TotalMilliseconds);
            Complete(log, startedTimestamp, RequestOutcome.UpstreamTimeout, StatusCodes.Status504GatewayTimeout, ProxyErrorCodes.UpstreamTimeout, "Upstream timed out while streaming the response.");
            context.Abort();
            return;
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException)
        {
            _circuitBreaker.RecordFailure(resolved.Destination.Id);
            ProxyLog.UpstreamUnreachable(_logger, resolved.Key, resolved.Destination.Key);
            Complete(log, startedTimestamp, RequestOutcome.UpstreamUnreachable, StatusCodes.Status502BadGateway, ProxyErrorCodes.UpstreamUnreachable, "Upstream connection failed while streaming the response.");
            context.Abort();
            return;
        }

        log.ResponseBytes = relayed;
        Complete(log, startedTimestamp, RequestOutcome.Forwarded, upstreamStatus, upstreamStatus >= 400 ? "upstream.http_error" : null, null);
        ProxyLog.Forwarded(_logger, resolved.Key, resolved.Destination.Key, resolved.Operation.HttpMethod, upstreamStatus, log.DurationMs ?? 0, relayed, send.Attempts);
    }

    private async Task<bool> TryApplyUpstreamAuthenticationAsync(HttpRequestMessage request, Destination destination, CancellationToken cancellationToken)
    {
        switch (destination.AuthType)
        {
            case UpstreamAuthType.None:
                return true;

            case UpstreamAuthType.ApiKeyHeader:
            {
                if (string.IsNullOrWhiteSpace(destination.AuthHeaderName) || string.IsNullOrWhiteSpace(destination.AuthSecretReference))
                {
                    return false;
                }

                var secret = await _secrets.GetSecretStringAsync(destination.AuthSecretReference, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrEmpty(secret) || !HeaderPolicy.IsSafeHeaderValue(secret))
                {
                    return false;
                }

                request.Headers.TryAddWithoutValidation(destination.AuthHeaderName, secret);
                return true;
            }

            case UpstreamAuthType.BearerToken:
            {
                if (string.IsNullOrWhiteSpace(destination.AuthSecretReference))
                {
                    return false;
                }

                var token = await _secrets.GetSecretStringAsync(destination.AuthSecretReference, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrEmpty(token) || !HeaderPolicy.IsSafeHeaderValue(token))
                {
                    return false;
                }

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return true;
            }

            default:
                return false;
        }
    }

    private async Task RejectConfigurationAsync(HttpContext context, RequestLog log, long startedTimestamp, ResolvedOperation resolved, string detail, string correlationId)
    {
        ProxyLog.InvalidConfiguration(_logger, resolved.Key, detail);
        // Internal detail goes to the log only; the caller learns that configuration is invalid, nothing more.
        await RejectAsync(context, log, startedTimestamp, new ProxyRejection(StatusCodes.Status500InternalServerError, ProxyErrorCodes.InvalidConfiguration, "The operation is not correctly configured."), correlationId).ConfigureAwait(false);
    }

    /// <summary>Writes the public error response for a request that must not be forwarded. Auditing happens centrally in <see cref="ExecuteAsync"/>.</summary>
    private async Task RejectAsync(HttpContext context, RequestLog log, long startedTimestamp, ProxyRejection rejection, string correlationId)
    {
        Complete(log, startedTimestamp, RequestOutcome.Rejected, rejection.StatusCode, rejection.Code, rejection.AuditDetail);
        ProxyLog.Rejected(_logger, rejection.Code, rejection.StatusCode, log.OperationKey);
        await context.WriteProblemAsync(rejection, correlationId).ConfigureAwait(false);
    }

    private void Complete(RequestLog log, long startedTimestamp, RequestOutcome outcome, int proxyStatus, string? reasonCode, string? reasonDetail)
    {
        var elapsed = Stopwatch.GetElapsedTime(startedTimestamp);
        log.CompletedAtUtc = _time.GetUtcNow().UtcDateTime;
        log.DurationMs = (long)elapsed.TotalMilliseconds;
        log.Outcome = outcome;
        log.ProxyStatusCode = proxyStatus;
        log.ReasonCode = reasonCode;
        log.ReasonDetail = reasonDetail is { Length: > 500 } ? reasonDetail[..500] : reasonDetail;
    }

    private static bool TryParseObject(byte[] plaintext, out JsonDocument? document)
    {
        document = null;
        try
        {
            var parsed = JsonDocument.Parse(plaintext, new JsonDocumentOptions { MaxDepth = 32 });
            if (parsed.RootElement.ValueKind != JsonValueKind.Object)
            {
                parsed.Dispose();
                return false;
            }

            document = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
