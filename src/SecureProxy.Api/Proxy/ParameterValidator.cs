using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Proxy;

/// <summary>Validated, typed parameters split by their configured location.</summary>
public sealed class BoundParameters
{
    public Dictionary<string, string> Path { get; } = new(StringComparer.Ordinal);
    public List<KeyValuePair<string, string>> Query { get; } = [];
    public JsonObject? Body { get; set; }
}

public sealed record ParameterValidationResult(BoundParameters? Parameters, IReadOnlyList<ParameterError> Errors)
{
    public bool Succeeded => Errors.Count == 0 && Parameters is not null;
}

public interface IParameterValidator
{
    ParameterValidationResult Validate(ResolvedOperation operation, JsonElement json);
}

/// <summary>
/// Applies the operation's <see cref="ParameterRule"/>s to the caller supplied <c>json</c> object.
/// Rules: required/optional, data type, length and range, regex pattern (with a match timeout), allowed values.
/// Unknown members are rejected unless the operation explicitly allows them, in which case they are forwarded in the
/// body (methods with a body) or the query string (methods without).
/// </summary>
public sealed class ParameterValidator : IParameterValidator
{
    private const int MaxReportedErrors = 20;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly string[] BodyMethods = ["POST", "PUT", "PATCH"];

    public ParameterValidationResult Validate(ResolvedOperation operation, JsonElement json)
    {
        var errors = new List<ParameterError>();
        var bound = new BoundParameters();
        var method = operation.Operation.HttpMethod.ToUpperInvariant();
        var methodHasBody = BodyMethods.Contains(method, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        foreach (var member in json.EnumerateObject())
        {
            if (member.Name == ProxyEnvelope.UrlIdMember)
            {
                continue; // consistency assertion handled by the executor, never forwarded
            }

            if (!members.TryAdd(member.Name, member.Value))
            {
                AddError(errors, member.Name, "duplicate", "Parameter is specified more than once.");
            }
        }

        foreach (var rule in operation.ParameterRules)
        {
            seen.Add(rule.Name);
            if (!members.TryGetValue(rule.Name, out var value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                // A path segment cannot be omitted, so path parameters are required regardless of the flag.
                if (rule.IsRequired || rule.Location == ParameterLocation.Path)
                {
                    AddError(errors, rule.Name, "required", "Parameter is required.");
                }

                continue;
            }

            if (rule.Location == ParameterLocation.Body && !methodHasBody)
            {
                // Mis-configuration: the operation cannot carry a body. Fail closed rather than silently dropping data.
                AddError(errors, rule.Name, "configuration", "Parameter location is not valid for the operation's HTTP method.");
                continue;
            }

            if (!TryConvert(rule, value, errors, out var scalar, out var node))
            {
                continue;
            }

            Bind(bound, rule.Location, rule.Name, scalar, node);
        }

        foreach (var (name, value) in members)
        {
            if (seen.Contains(name))
            {
                continue;
            }

            if (!operation.Operation.AllowUnknownParameters)
            {
                AddError(errors, name, "unknown", "Parameter is not permitted for this operation.");
                continue;
            }

            if (name.Length > 100 || !IsSafeName(name))
            {
                AddError(errors, name.Length > 64 ? name[..64] : name, "invalid_name", "Parameter name is not acceptable.");
                continue;
            }

            if (methodHasBody)
            {
                (bound.Body ??= new JsonObject())[name] = JsonNode.Parse(value.GetRawText());
            }
            else if (value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
            {
                bound.Query.Add(new KeyValuePair<string, string>(name, ToScalarString(value)));
            }
            else
            {
                AddError(errors, name, "unsupported", "Only scalar values can be forwarded in the query string.");
            }
        }

        return errors.Count == 0
            ? new ParameterValidationResult(bound, errors)
            : new ParameterValidationResult(null, errors);
    }

    private static void Bind(BoundParameters bound, ParameterLocation location, string name, string? scalar, JsonNode? node)
    {
        switch (location)
        {
            case ParameterLocation.Path:
                bound.Path[name] = scalar ?? string.Empty;
                break;
            case ParameterLocation.Query:
                bound.Query.Add(new KeyValuePair<string, string>(name, scalar ?? string.Empty));
                break;
            case ParameterLocation.Body:
                (bound.Body ??= new JsonObject())[name] = node ?? JsonValue.Create(scalar);
                break;
        }
    }

    private static bool TryConvert(ParameterRule rule, JsonElement value, List<ParameterError> errors, out string? scalar, out JsonNode? node)
    {
        scalar = null;
        node = null;

        switch (rule.DataType)
        {
            case ParameterDataType.String:
                if (value.ValueKind != JsonValueKind.String)
                {
                    return Fail(errors, rule.Name, "type", "Expected a string.");
                }

                var s = value.GetString()!;
                if (s.Length == 0 && rule.IsRequired)
                {
                    return Fail(errors, rule.Name, "required", "Parameter must not be empty.");
                }

                if (rule.MaxLength is { } max && s.Length > max)
                {
                    return Fail(errors, rule.Name, "max_length", $"Value exceeds the maximum length of {max}.");
                }

                if (s.Any(char.IsControl))
                {
                    return Fail(errors, rule.Name, "control_characters", "Control characters are not permitted.");
                }

                if (!string.IsNullOrEmpty(rule.Pattern) && !MatchesPattern(rule.Pattern, s))
                {
                    return Fail(errors, rule.Name, "pattern", "Value does not match the required format.");
                }

                if (!string.IsNullOrEmpty(rule.AllowedValues) &&
                    !rule.AllowedValues.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Contains(s, StringComparer.Ordinal))
                {
                    return Fail(errors, rule.Name, "not_allowed", "Value is not one of the permitted values.");
                }

                scalar = s;
                node = JsonValue.Create(s);
                return true;

            case ParameterDataType.Integer:
                if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var l))
                {
                    return Fail(errors, rule.Name, "type", "Expected an integer.");
                }

                if (!InRange(rule, l))
                {
                    return Fail(errors, rule.Name, "range", "Value is outside the permitted range.");
                }

                scalar = l.ToString(CultureInfo.InvariantCulture);
                node = JsonValue.Create(l);
                return true;

            case ParameterDataType.Number:
                if (value.ValueKind != JsonValueKind.Number || !value.TryGetDecimal(out var d))
                {
                    return Fail(errors, rule.Name, "type", "Expected a number.");
                }

                if (!InRange(rule, d))
                {
                    return Fail(errors, rule.Name, "range", "Value is outside the permitted range.");
                }

                scalar = d.ToString(CultureInfo.InvariantCulture);
                node = JsonValue.Create(d);
                return true;

            case ParameterDataType.Boolean:
                if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return Fail(errors, rule.Name, "type", "Expected a boolean.");
                }

                var b = value.GetBoolean();
                scalar = b ? "true" : "false";
                node = JsonValue.Create(b);
                return true;

            case ParameterDataType.Guid:
                if (value.ValueKind != JsonValueKind.String || !Guid.TryParseExact(value.GetString(), "D", out var g))
                {
                    return Fail(errors, rule.Name, "type", "Expected a GUID in canonical format.");
                }

                scalar = g.ToString("D");
                node = JsonValue.Create(scalar);
                return true;

            case ParameterDataType.DateTime:
                if (value.ValueKind != JsonValueKind.String ||
                    !DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
                {
                    return Fail(errors, rule.Name, "type", "Expected an ISO-8601 date/time.");
                }

                scalar = dto.ToString("O", CultureInfo.InvariantCulture);
                node = JsonValue.Create(scalar);
                return true;

            case ParameterDataType.Object:
            case ParameterDataType.Array:
                var expectedKind = rule.DataType == ParameterDataType.Object ? JsonValueKind.Object : JsonValueKind.Array;
                if (value.ValueKind != expectedKind)
                {
                    return Fail(errors, rule.Name, "type", $"Expected a JSON {(expectedKind == JsonValueKind.Object ? "object" : "array")}.");
                }

                if (rule.Location != ParameterLocation.Body)
                {
                    return Fail(errors, rule.Name, "configuration", "Structured values can only be sent in the body.");
                }

                var raw = value.GetRawText();
                if (rule.MaxLength is { } maxRaw && raw.Length > maxRaw)
                {
                    return Fail(errors, rule.Name, "max_length", $"Value exceeds the maximum size of {maxRaw} characters.");
                }

                node = JsonNode.Parse(raw);
                return true;

            default:
                return Fail(errors, rule.Name, "configuration", "Unsupported parameter data type.");
        }
    }

    private static bool InRange(ParameterRule rule, decimal value)
        => (rule.MinValue is null || value >= rule.MinValue.Value) && (rule.MaxValue is null || value <= rule.MaxValue.Value);

    private static bool MatchesPattern(string pattern, string input)
    {
        try
        {
            // Always anchor the whole value, even if the configured pattern already starts with '^' or ends with '$'.
            var anchored = "^(?:" + pattern + ")$";
            return Regex.IsMatch(input, anchored, RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, RegexTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false; // fail closed on pathological input
        }
        catch (ArgumentException)
        {
            return false; // invalid pattern in configuration: fail closed
        }
    }

    private static bool IsSafeName(string name) => name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');

    private static string ToScalarString(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => value.GetRawText()
    };

    private static bool Fail(List<ParameterError> errors, string name, string code, string message)
    {
        AddError(errors, name, code, message);
        return false;
    }

    private static void AddError(List<ParameterError> errors, string name, string code, string message)
    {
        if (errors.Count < MaxReportedErrors)
        {
            errors.Add(new ParameterError(name, code, message));
        }
    }
}
