using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Extensions;

namespace SecureProxy.Api.Proxy;

public sealed record UriBuildResult(Uri? Uri, string? Error, bool CallerFault = false)
{
    public bool Succeeded => Uri is not null;

    public static UriBuildResult ConfigurationError(string error) => new(null, error, CallerFault: false);
    public static UriBuildResult ParameterError(string error) => new(null, error, CallerFault: true);
}

/// <summary>
/// Builds the upstream URI from <b>trusted</b> configuration (destination base URL + operation path template) and
/// validated path/query parameters. Defends against path traversal and host/scheme smuggling:
/// <list type="bullet">
/// <item>placeholders must occupy whole segments; a template cannot contain <c>.</c>/<c>..</c> segments;</item>
/// <item>path values are restricted to a conservative character set (no <c>/</c>, <c>\</c>, <c>%</c>, <c>?</c>, <c>#</c>, control characters)
///   and may never be <c>.</c> or <c>..</c> or contain <c>..</c>, so an upstream that decodes <c>%2F</c>/<c>%2E</c> cannot be tricked;</item>
/// <item>the final absolute URI must stay under the base URL (same scheme, host, port, and path prefix).</item>
/// </list>
/// </summary>
public static partial class UpstreamUriBuilder
{
    public static UriBuildResult Build(string baseUrl, string pathTemplate, IReadOnlyDictionary<string, string> pathValues, IEnumerable<KeyValuePair<string, string>> query, string[]? allowedSchemes, string? allowedPorts)
    {
        if (!Uri.TryCreate(NormaliseBase(baseUrl), UriKind.Absolute, out var baseUri) || string.IsNullOrEmpty(baseUri.Host))
        {
            return new UriBuildResult(null, "Destination base URL is invalid.");
        }

        if (allowedSchemes is { Length: > 0 } && !allowedSchemes.Contains(baseUri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            return new UriBuildResult(null, "Destination scheme is not permitted.");
        }

        if (!string.IsNullOrWhiteSpace(allowedPorts))
        {
            var ports = allowedPorts.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (!ports.Contains(baseUri.Port.ToString(), StringComparer.Ordinal))
            {
                return new UriBuildResult(null, "Destination port is not permitted.");
            }
        }

        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment) || !string.IsNullOrEmpty(baseUri.UserInfo))
        {
            return new UriBuildResult(null, "Destination base URL must not contain query, fragment or user information.");
        }

        var template = pathTemplate.Trim().TrimStart('/');
        if (template.Contains("://", StringComparison.Ordinal) || template.Contains('?') || template.Contains('#') || template.Contains('\\'))
        {
            return new UriBuildResult(null, "Operation path template is invalid.");
        }

        var builder = new StringBuilder();
        var used = new HashSet<string>(StringComparer.Ordinal);
        if (template.Length > 0)
        {
            var segments = template.Split('/');
            for (var i = 0; i < segments.Length; i++)
            {
                var segment = segments[i];
                if (segment.Length == 0)
                {
                    if (i == segments.Length - 1)
                    {
                        break; // trailing slash in template
                    }

                    return new UriBuildResult(null, "Operation path template contains an empty segment.");
                }

                if (segment is "." or "..")
                {
                    return new UriBuildResult(null, "Operation path template contains a dot segment.");
                }

                string rendered;
                var placeholder = PlaceholderRegex().Match(segment);
                if (placeholder.Success)
                {
                    var name = placeholder.Groups["name"].Value;
                    if (!pathValues.TryGetValue(name, out var value))
                    {
                        return new UriBuildResult(null, $"No value bound for path parameter '{name}'.");
                    }

                    if (!IsSafePathValue(value))
                    {
                        return UriBuildResult.ParameterError($"Path parameter '{name}' contains characters that are not permitted.");
                    }

                    used.Add(name);
                    rendered = Uri.EscapeDataString(value);
                }
                else
                {
                    if (segment.Contains('{') || segment.Contains('}'))
                    {
                        return new UriBuildResult(null, "Placeholders must occupy a whole path segment.");
                    }

                    if (!IsSafeLiteralSegment(segment))
                    {
                        return new UriBuildResult(null, "Operation path template contains characters that are not permitted.");
                    }

                    rendered = segment;
                }

                if (builder.Length > 0)
                {
                    builder.Append('/');
                }

                builder.Append(rendered);
            }
        }

        if (used.Count != pathValues.Count)
        {
            return new UriBuildResult(null, "A path parameter is not referenced by the operation path template.");
        }

        var relative = builder.ToString();
        var queryString = BuildQuery(query);
        if (!Uri.TryCreate(baseUri, relative + queryString, out var result))
        {
            return UriBuildResult.ParameterError("The upstream URL could not be constructed.");
        }

        // Belt and braces: the final URL must be "inside" the configured base URL.
        if (!string.Equals(result.Scheme, baseUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(result.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)
            || result.Port != baseUri.Port
            || !result.AbsolutePath.StartsWith(baseUri.AbsolutePath, StringComparison.Ordinal)
            || result.AbsolutePath.Contains("/../", StringComparison.Ordinal)
            || result.AbsolutePath.Contains("/./", StringComparison.Ordinal)
            || result.AbsolutePath.EndsWith("/..", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(result.UserInfo))
        {
            return UriBuildResult.ParameterError("The upstream URL escaped the configured destination.");
        }

        return new UriBuildResult(result, null);
    }

    /// <summary>Normalises a destination base URL so it always ends with '/' (required for correct relative resolution).</summary>
    public static string NormaliseBase(string baseUrl)
    {
        var trimmed = baseUrl.Trim();
        return trimmed.EndsWith('/') ? trimmed : trimmed + "/";
    }

    /// <summary>Conservative allow-list for values interpolated into the path.</summary>
    public static bool IsSafePathValue(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 512 || value is "." or "..")
        {
            return false;
        }

        if (value.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '@' or ':' or '+' or '=' or ',' or ' ')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool IsSafeLiteralSegment(string segment)
        => segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '@' or ':' or '+' or '=' or ',');

    private static string BuildQuery(IEnumerable<KeyValuePair<string, string>> query)
    {
        var qb = new QueryBuilder();
        var any = false;
        foreach (var (name, value) in query)
        {
            qb.Add(name, value);
            any = true;
        }

        return any ? qb.ToQueryString().Value ?? string.Empty : string.Empty;
    }

    [GeneratedRegex("^\\{(?<name>[A-Za-z_][A-Za-z0-9_]{0,99})\\}$")]
    private static partial Regex PlaceholderRegex();
}
