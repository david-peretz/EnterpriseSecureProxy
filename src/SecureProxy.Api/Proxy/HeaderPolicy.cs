using Microsoft.Extensions.Primitives;

namespace SecureProxy.Api.Proxy;

/// <summary>
/// Decides which headers cross the proxy boundary. Everything is deny-by-default:
/// a request header is forwarded only if the operation allow-lists it <em>and</em> it is not a hop-by-hop,
/// credential or routing header; a response header is relayed only if it is on the default allow-list or the
/// operation's response allow-list.
/// </summary>
public static class HeaderPolicy
{
    /// <summary>Headers that can never be forwarded upstream, regardless of configuration.</summary>
    public static readonly IReadOnlySet<string> NeverForwardRequestHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // hop-by-hop (RFC 9110 §7.6.1) and framing
        "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Content-Length", "Content-Type", "Expect",
        // caller credentials / session state: the proxy authenticates to upstreams with its own credentials
        "Authorization", "Proxy-Authorization", "Proxy-Authenticate", "Cookie", "Set-Cookie",
        // routing / origin information that must come from configuration
        "Host", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "Via", "Origin", "Referer",
        // security sensitive or proxy owned
        "X-Api-Key", "X-Admin-ApiKey", "Idempotency-Key", "Accept-Encoding"
    };

    /// <summary>Upstream response headers that are never relayed to the caller.</summary>
    public static readonly IReadOnlySet<string> NeverRelayResponseHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Content-Length",
        "Set-Cookie", "Set-Cookie2", "WWW-Authenticate", "Proxy-Authenticate", "Server", "X-Powered-By", "Location", "Content-Location",
        "Alt-Svc", "Strict-Transport-Security", "Public-Key-Pins", "X-AspNet-Version"
    };

    /// <summary>
    /// Headers that describe how to decode the relayed body. The proxy copies the body verbatim (no decompression), so these
    /// must travel with it regardless of allow-lists or the caller could not interpret the bytes.
    /// </summary>
    public static readonly IReadOnlySet<string> AlwaysRelayResponseHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Type", "Content-Encoding"
    };

    private const int MaxHeaderValueLength = 8 * 1024;

    /// <summary>Returns the caller headers that may be copied to the upstream request.</summary>
    public static IEnumerable<KeyValuePair<string, string>> SelectRequestHeaders(IHeaderDictionary incoming, IReadOnlySet<string> operationAllowlist)
    {
        foreach (var name in operationAllowlist)
        {
            if (NeverForwardRequestHeaders.Contains(name) || !incoming.TryGetValue(name, out var values))
            {
                continue;
            }

            foreach (var value in values)
            {
                if (IsSafeHeaderValue(value))
                {
                    yield return new KeyValuePair<string, string>(name, value!);
                }
            }
        }
    }

    /// <summary>Returns the upstream response headers that may be relayed to the caller.</summary>
    public static IEnumerable<KeyValuePair<string, StringValues>> SelectResponseHeaders(HttpResponseMessage upstream, IReadOnlySet<string> defaultAllowlist, IReadOnlySet<string> operationAllowlist)
    {
        foreach (var header in upstream.Headers.Concat(upstream.Content.Headers))
        {
            if (NeverRelayResponseHeaders.Contains(header.Key))
            {
                continue;
            }

            if (!AlwaysRelayResponseHeaders.Contains(header.Key) && !defaultAllowlist.Contains(header.Key) && !operationAllowlist.Contains(header.Key))
            {
                continue;
            }

            var values = header.Value.Where(IsSafeHeaderValue).ToArray();
            if (values.Length > 0)
            {
                yield return new KeyValuePair<string, StringValues>(header.Key, new StringValues(values));
            }
        }
    }

    public static bool IsSafeHeaderValue(string? value)
    {
        if (value is null || value.Length > MaxHeaderValueLength)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is '\r' or '\n' or '\0' || (char.IsControl(c) && c != '\t'))
            {
                return false;
            }
        }

        return true;
    }
}
