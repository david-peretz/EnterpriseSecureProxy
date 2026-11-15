namespace SecureProxy.Api.Infrastructure;

/// <summary>
/// Source-generated structured log messages. Only metadata is logged: never headers, bodies, credentials or key material.
/// </summary>
internal static partial class ProxyLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Request rejected before forwarding: {ReasonCode} (status {StatusCode}) operation={OperationKey}")]
    public static partial void Rejected(ILogger logger, string reasonCode, int statusCode, string? operationKey);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Information, Message = "Forwarded operation={OperationKey} destination={DestinationKey} method={Method} upstreamStatus={UpstreamStatus} durationMs={DurationMs} responseBytes={ResponseBytes} attempts={Attempts}")]
    public static partial void Forwarded(ILogger logger, string operationKey, string destinationKey, string method, int upstreamStatus, long durationMs, long responseBytes, int attempts);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Warning, Message = "Upstream timeout operation={OperationKey} destination={DestinationKey} timeoutMs={TimeoutMs}")]
    public static partial void UpstreamTimeout(ILogger logger, string operationKey, string destinationKey, long timeoutMs);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "Upstream unreachable operation={OperationKey} destination={DestinationKey}")]
    public static partial void UpstreamUnreachable(ILogger logger, string operationKey, string destinationKey);

    [LoggerMessage(EventId = 1004, Level = LogLevel.Information, Message = "Caller cancelled operation={OperationKey} after {ElapsedMs} ms (forwarded={Forwarded})")]
    public static partial void CallerCancelled(ILogger logger, string? operationKey, long elapsedMs, bool forwarded);

    [LoggerMessage(EventId = 1005, Level = LogLevel.Warning, Message = "Upstream response exceeded {MaxBytes} bytes for operation={OperationKey}; connection aborted after {BytesRelayed} bytes")]
    public static partial void ResponseTooLarge(ILogger logger, long maxBytes, string operationKey, long bytesRelayed);

    [LoggerMessage(EventId = 1006, Level = LogLevel.Error, Message = "Unhandled proxy error operation={OperationKey} forwarded={Forwarded}")]
    public static partial void UnhandledError(ILogger logger, Exception exception, string? operationKey, bool forwarded);

    [LoggerMessage(EventId = 1007, Level = LogLevel.Error, Message = "Invalid configuration for operation={OperationKey}: {Detail}")]
    public static partial void InvalidConfiguration(ILogger logger, string operationKey, string detail);

    [LoggerMessage(EventId = 1008, Level = LogLevel.Warning, Message = "Payload decryption failed for operation={OperationKey}: {Failure}")]
    public static partial void DecryptionFailed(ILogger logger, string operationKey, string failure);
}
