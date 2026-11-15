using System.Net;
using Microsoft.AspNetCore.Http;
using SecureProxy.Api.Proxy;

namespace SecureProxy.Tests.Unit;

public sealed class HeaderPolicyTests
{
    [Fact] // Required test 10 (unit level)
    public void Only_allow_listed_non_sensitive_request_headers_are_selected()
    {
        var incoming = new HeaderDictionary
        {
            ["X-Tenant-Id"] = "t1",
            ["X-Trace"] = "abc",
            ["Authorization"] = "Bearer secret",
            ["Cookie"] = "session=1",
            ["Host"] = "proxy.internal",
            ["X-Forwarded-For"] = "10.0.0.1",
            ["Content-Length"] = "12",
            ["X-Injected"] = "bad\r\nvalue"
        };

        // Even an administrator cannot allow-list credential, hop-by-hop or routing headers.
        var allowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "X-Tenant-Id", "Authorization", "Cookie", "Host", "X-Forwarded-For", "Content-Length", "X-Injected" };

        var selected = HeaderPolicy.SelectRequestHeaders(incoming, allowlist).ToList();

        var single = Assert.Single(selected);
        Assert.Equal("X-Tenant-Id", single.Key);
        Assert.Equal("t1", single.Value);
    }

    [Fact]
    public void Response_headers_follow_default_and_operation_allow_lists_but_never_leak_internals()
    {
        var upstream = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        upstream.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
        upstream.Headers.TryAddWithoutValidation("X-Request-Cost", "3");
        upstream.Headers.TryAddWithoutValidation("Set-Cookie", "a=b");
        upstream.Headers.TryAddWithoutValidation("Server", "nginx");
        upstream.Headers.TryAddWithoutValidation("Location", "http://internal-host/redirect");
        upstream.Headers.TryAddWithoutValidation("X-Internal", "node-3");
        upstream.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");

        var defaults = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Content-Type", "Cache-Control" };
        var operationAllowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "X-Request-Cost", "Set-Cookie", "Location" };

        var names = HeaderPolicy.SelectResponseHeaders(upstream, defaults, operationAllowlist).Select(h => h.Key).ToList();

        Assert.Contains("Cache-Control", names);
        Assert.Contains("Content-Type", names);
        Assert.Contains("X-Request-Cost", names);
        Assert.Contains("Content-Encoding", names); // the body is relayed verbatim, so its encoding must travel with it
        Assert.DoesNotContain("Set-Cookie", names);
        Assert.DoesNotContain("Server", names);
        Assert.DoesNotContain("Location", names);
        Assert.DoesNotContain("X-Internal", names);
    }

    [Theory]
    [InlineData("plain", true)]
    [InlineData("with\ttab", true)]
    [InlineData("crlf\r\ninjection", false)]
    [InlineData("nul\0", false)]
    [InlineData(null, false)]
    public void Header_value_safety(string? value, bool expected) => Assert.Equal(expected, HeaderPolicy.IsSafeHeaderValue(value));
}
