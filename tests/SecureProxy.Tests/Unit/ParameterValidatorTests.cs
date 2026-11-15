using System.Text.Json;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;

namespace SecureProxy.Tests.Unit;

public sealed class ParameterValidatorTests
{
    private readonly ParameterValidator _validator = new();

    [Fact]
    public void Binds_each_parameter_to_its_configured_location()
    {
        var operation = Operation("POST", allowUnknown: false,
            Rule("id", ParameterLocation.Path, ParameterDataType.String, required: true),
            Rule("page", ParameterLocation.Query, ParameterDataType.Integer, min: 1),
            Rule("active", ParameterLocation.Query, ParameterDataType.Boolean),
            Rule("payload", ParameterLocation.Body, ParameterDataType.Object, maxLength: 1000),
            Rule("when", ParameterLocation.Body, ParameterDataType.DateTime));

        var result = _validator.Validate(operation, Json("""{ "urlId": "x", "id": "abc", "page": 3, "active": true, "payload": { "k": [1,2] }, "when": "2026-11-08T10:00:00+02:00" }"""));

        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(e => $"{e.Name}:{e.Code}")));
        var bound = result.Parameters!;
        Assert.Equal("abc", bound.Path["id"]);
        Assert.Contains(bound.Query, kv => kv.Key == "page" && kv.Value == "3");
        Assert.Contains(bound.Query, kv => kv.Key == "active" && kv.Value == "true");
        Assert.Equal("[1,2]", bound.Body!["payload"]!["k"]!.ToJsonString());
        Assert.Equal("2026-11-08T08:00:00.0000000+00:00", bound.Body["when"]!.GetValue<string>()); // normalised to UTC
        Assert.False(bound.Body.ContainsKey("urlId"));
    }

    [Fact]
    public void Reports_all_problems_at_once()
    {
        var operation = Operation("GET", allowUnknown: false,
            Rule("a", ParameterLocation.Query, ParameterDataType.Integer, required: true, min: 0, max: 10),
            Rule("b", ParameterLocation.Query, ParameterDataType.String, maxLength: 3, pattern: "[a-z]+"),
            Rule("c", ParameterLocation.Query, ParameterDataType.Guid));

        var result = _validator.Validate(operation, Json("""{ "a": 11, "b": "ABCD", "c": "nope", "d": 1 }"""));

        Assert.False(result.Succeeded);
        var codes = result.Errors.ToDictionary(e => e.Name, e => e.Code);
        Assert.Equal("range", codes["a"]);
        Assert.Equal("max_length", codes["b"]);
        Assert.Equal("type", codes["c"]);
        Assert.Equal("unknown", codes["d"]);
    }

    [Theory]
    [InlineData("[A-Z]{3}")]
    [InlineData("^[A-Z]{3}")]
    [InlineData("[A-Z]{3}$")]
    [InlineData("^[A-Z]{3}$")]
    public void Pattern_is_anchored_so_partial_matches_do_not_pass(string pattern)
    {
        var operation = Operation("GET", allowUnknown: false, Rule("code", ParameterLocation.Query, ParameterDataType.String, pattern: pattern));

        Assert.True(_validator.Validate(operation, Json("""{ "code": "ABC" }""")).Succeeded);
        Assert.False(_validator.Validate(operation, Json("""{ "code": "xxABCxx" }""")).Succeeded);
        Assert.False(_validator.Validate(operation, Json("""{ "code": "ABCxx" }""")).Succeeded);
        Assert.False(_validator.Validate(operation, Json("""{ "code": "xxABC" }""")).Succeeded);
        Assert.False(_validator.Validate(operation, Json("""{ "code": "ABC\n" }""")).Succeeded);
    }

    [Fact]
    public void Path_parameters_are_required_even_when_configured_as_optional()
    {
        var operation = Operation("GET", allowUnknown: false, Rule("id", ParameterLocation.Path, ParameterDataType.String, required: false));

        var result = _validator.Validate(operation, Json("""{ }"""));

        Assert.Equal("required", Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void Null_counts_as_missing_and_body_rules_are_invalid_for_get()
    {
        var required = Operation("GET", allowUnknown: false, Rule("q", ParameterLocation.Query, ParameterDataType.String, required: true));
        Assert.Equal("required", Assert.Single(_validator.Validate(required, Json("""{ "q": null }""")).Errors).Code);

        var misconfigured = Operation("GET", allowUnknown: false, Rule("data", ParameterLocation.Body, ParameterDataType.Object));
        Assert.Equal("configuration", Assert.Single(_validator.Validate(misconfigured, Json("""{ "data": {} }""")).Errors).Code);
    }

    [Fact]
    public void Unknown_parameters_go_to_body_or_query_when_allowed_but_names_stay_safe()
    {
        var post = Operation("POST", allowUnknown: true);
        var bound = _validator.Validate(post, Json("""{ "x": 1, "y": { "z": true } }""")).Parameters!;
        Assert.Equal(1, bound.Body!["x"]!.GetValue<int>());
        Assert.True(bound.Body["y"]!["z"]!.GetValue<bool>());

        var get = Operation("GET", allowUnknown: true);
        var getResult = _validator.Validate(get, Json("""{ "x": 1, "y": { "z": true } }"""));
        Assert.False(getResult.Succeeded); // structured values cannot travel in a query string
        Assert.Equal("unsupported", Assert.Single(getResult.Errors).Code);

        var weird = _validator.Validate(post, Json("""{ "x y": 1 }"""));
        Assert.Equal("invalid_name", Assert.Single(weird.Errors).Code);
    }

    private static ResolvedOperation Operation(string method, bool allowUnknown, params ParameterRule[] rules)
    {
        var destination = new Destination { Id = Guid.NewGuid(), Key = "d", BaseUrl = "https://d.test/", IsEnabled = true };
        var operation = new Operation { Id = Guid.NewGuid(), Key = "op", HttpMethod = method, PathTemplate = "x", Destination = destination, AllowUnknownParameters = allowUnknown };
        foreach (var rule in rules)
        {
            operation.ParameterRules.Add(rule);
        }

        return new ResolvedOperation(operation);
    }

    private static ParameterRule Rule(string name, ParameterLocation location, ParameterDataType type, bool required = false, int? maxLength = null, decimal? min = null, decimal? max = null, string? pattern = null)
        => new() { Id = Guid.NewGuid(), Name = name, Location = location, DataType = type, IsRequired = required, MaxLength = maxLength, MinValue = min, MaxValue = max, Pattern = pattern };

    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();
}
