using SecureProxy.Api.Proxy;

namespace SecureProxy.Tests.Unit;

public sealed class UpstreamUriBuilderTests
{
    private static readonly string[] HttpsOnly = ["https"];

    [Fact]
    public void Builds_url_from_trusted_base_template_and_encoded_values()
    {
        var result = UpstreamUriBuilder.Build("https://api.example.com/v1", "customers/{id}/orders", new Dictionary<string, string> { ["id"] = "a b+c" },
            [new("page", "2"), new("q", "x&y")], HttpsOnly, "443");

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("https://api.example.com/v1/customers/a%20b%2Bc/orders?page=2&q=x%26y", result.Uri!.AbsoluteUri);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("../x")]
    [InlineData("a/../b")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("%2e%2e")]
    [InlineData("a?b")]
    [InlineData("a#b")]
    [InlineData("")]
    [InlineData("a\nb")]
    [InlineData("ok..")]
    public void Rejects_unsafe_path_values_as_caller_faults(string value)
    {
        var result = UpstreamUriBuilder.Build("https://api.example.com/v1/", "customers/{id}", new Dictionary<string, string> { ["id"] = value }, [], HttpsOnly, null);

        Assert.False(result.Succeeded);
        Assert.True(result.CallerFault);
    }

    [Theory]
    [InlineData("../{id}")]
    [InlineData("customers/./{id}")]
    [InlineData("customers//{id}")]
    [InlineData("https://evil.example/{id}")]
    [InlineData("customers/{id}.json")]
    [InlineData("customers/{id}?x=1")]
    public void Rejects_invalid_templates_as_configuration_errors(string template)
    {
        var result = UpstreamUriBuilder.Build("https://api.example.com/v1/", template, new Dictionary<string, string> { ["id"] = "1" }, [], HttpsOnly, null);

        Assert.False(result.Succeeded);
        Assert.False(result.CallerFault);
    }

    [Fact]
    public void Rejects_disallowed_scheme_and_port()
    {
        Assert.False(UpstreamUriBuilder.Build("http://api.example.com/", "x", new Dictionary<string, string>(), [], HttpsOnly, null).Succeeded);
        Assert.False(UpstreamUriBuilder.Build("https://api.example.com:8443/", "x", new Dictionary<string, string>(), [], HttpsOnly, "443").Succeeded);
        Assert.True(UpstreamUriBuilder.Build("https://api.example.com:8443/", "x", new Dictionary<string, string>(), [], HttpsOnly, "443,8443").Succeeded);
    }

    [Fact]
    public void Rejects_bound_values_not_used_by_the_template_and_missing_values()
    {
        Assert.False(UpstreamUriBuilder.Build("https://api.example.com/", "customers", new Dictionary<string, string> { ["id"] = "1" }, [], HttpsOnly, null).Succeeded);
        Assert.False(UpstreamUriBuilder.Build("https://api.example.com/", "customers/{id}", new Dictionary<string, string>(), [], HttpsOnly, null).Succeeded);
    }

    [Fact]
    public void Base_url_without_trailing_slash_is_treated_as_a_directory()
    {
        var result = UpstreamUriBuilder.Build("https://api.example.com/v1", "items", new Dictionary<string, string>(), [], HttpsOnly, null);

        Assert.Equal("https://api.example.com/v1/items", result.Uri!.AbsoluteUri);
    }
}
