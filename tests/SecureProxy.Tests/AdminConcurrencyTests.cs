using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureProxy.Api.Admin;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>Configuration updates: optimistic concurrency (409), immediate effect on the proxy, and change history.</summary>
public sealed class AdminConcurrencyTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;

    public AdminConcurrencyTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact] // Required test 16
    public async Task Update_with_a_stale_concurrency_stamp_is_rejected_with_409()
    {
        var admin = _factory.CreateAdminClient();

        var current = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/customer.search");
        var stamp = current.GetProperty("concurrencyStamp").GetString()!;

        // First writer wins...
        var first = await admin.PutAsJsonAsync("/api/admin/operations/customer.search", new { maxRequestBytes = 4096, concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var newStamp = first.Headers.ETag!.Tag.Trim('"');
        Assert.NotEqual(stamp, newStamp);

        // ...the second writer still holds the old stamp and must be told to reload.
        var second = await admin.PutAsJsonAsync("/api/admin/operations/customer.search", new { maxRequestBytes = 8192, concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        var problem = await second.ReadJsonAsync();
        Assert.Equal(ProxyErrorCodes.ConcurrencyConflict, problem.GetProperty("code").GetString());
        Assert.Equal(newStamp, problem.GetProperty("currentConcurrencyStamp").GetString());
        Assert.Equal(newStamp, second.Headers.ETag!.Tag.Trim('"'));

        // The stale write did not go through.
        var reloaded = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/customer.search");
        Assert.Equal(4096, reloaded.GetProperty("maxRequestBytes").GetInt64());
    }

    [Fact] // Required test 16 (If-Match header variant + missing stamp)
    public async Task If_match_header_is_accepted_and_a_missing_stamp_is_rejected()
    {
        var admin = _factory.CreateAdminClient();
        var get = await admin.GetAsync("/api/admin/destinations/crm");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        var etag = get.Headers.ETag!.Tag;

        var withoutStamp = await admin.PutAsJsonAsync("/api/admin/destinations/crm", new { name = "CRM renamed" });
        Assert.Equal(HttpStatusCode.BadRequest, withoutStamp.StatusCode);

        var request = new HttpRequestMessage(HttpMethod.Put, "/api/admin/destinations/crm") { Content = JsonContent.Create(new { name = "CRM renamed" }) };
        request.Headers.TryAddWithoutValidation("If-Match", etag);
        var withHeader = await admin.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, withHeader.StatusCode);
        Assert.NotEqual(etag, withHeader.Headers.ETag!.Tag);
    }

    [Fact] // Required test 16 (service level: second writer holding the stamp the first writer consumed)
    public async Task Second_writer_with_the_same_stamp_is_rejected_after_the_first_commits()
    {
        var service = _factory.Services.GetRequiredService<ConfigurationAdminService>();
        var current = (await service.GetOperationAsync("order.bulk", CancellationToken.None))!;

        var winner = await service.UpdateOperationAsync("order.bulk", new UpdateOperationRequest(null, null, null, 700, null, null, null, null, null, null), current.ConcurrencyStamp, "test", "race-1", CancellationToken.None);
        Assert.NotEqual(current.ConcurrencyStamp, winner.ConcurrencyStamp);

        var loser = await Assert.ThrowsAsync<ConcurrencyConflictException>(() =>
            service.UpdateOperationAsync("order.bulk", new UpdateOperationRequest(null, null, null, 800, null, null, null, null, null, null), current.ConcurrencyStamp, "test", "race-2", CancellationToken.None));
        Assert.Equal(winner.ConcurrencyStamp, loser.CurrentStamp);

        await using var db = _factory.CreateDbContext();
        var row = await db.Operations.AsNoTracking().SingleAsync(o => o.Key == "order.bulk");
        Assert.Equal(700, row.MaxRequestBytes);
    }

    [Fact] // Required test 16 (true race: the database enforces the concurrency token in the UPDATE's WHERE clause)
    public async Task Concurrent_writers_racing_on_the_same_row_conflict_at_the_database()
    {
        await using var first = _factory.CreateDbContext();
        await using var second = _factory.CreateDbContext();

        // Both contexts load the same row (same ConcurrencyStamp) before either writes.
        var fromFirst = await first.Destinations.SingleAsync(d => d.Key == TestSeed.LegacyKey);
        var fromSecond = await second.Destinations.SingleAsync(d => d.Key == TestSeed.LegacyKey);
        Assert.Equal(fromFirst.ConcurrencyStamp, fromSecond.ConcurrencyStamp);

        fromFirst.Name = "Legacy (first writer)";
        fromFirst.ConcurrencyStamp = Guid.NewGuid().ToString("N");
        await first.SaveChangesAsync();

        fromSecond.Name = "Legacy (second writer)";
        fromSecond.ConcurrencyStamp = Guid.NewGuid().ToString("N");
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());

        await using var verify = _factory.CreateDbContext();
        Assert.Equal("Legacy (first writer)", (await verify.Destinations.AsNoTracking().SingleAsync(d => d.Key == TestSeed.LegacyKey)).Name);
    }

    [Fact]
    public async Task Disabling_an_operation_takes_effect_immediately_and_is_recorded_in_history()
    {
        var admin = _factory.CreateAdminClient();
        var proxy = _factory.CreateProxyClient();

        var ok = await proxy.ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(1, _factory.Upstream.Count);

        var current = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/customer.get");
        var disable = await admin.PutAsJsonAsync("/api/admin/operations/customer.get", new { isEnabled = false, concurrencyStamp = current.GetProperty("concurrencyStamp").GetString() });
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        var rejected = await proxy.ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } });
        Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        Assert.Equal(1, _factory.Upstream.Count); // cached configuration was invalidated: nothing more reached the upstream

        var history = await admin.GetFromJsonAsync<JsonElement>("/api/admin/configuration-changes?entityType=Operation&entityKey=customer.get");
        var change = history.EnumerateArray().First();
        Assert.Equal("Updated", change.GetProperty("action").GetString());
        Assert.Equal("admin-api-key", change.GetProperty("changedBy").GetString());
        var diff = change.GetProperty("changes").GetProperty("IsEnabled");
        Assert.True(diff.GetProperty("from").GetBoolean());
        Assert.False(diff.GetProperty("to").GetBoolean());

        // restore for other tests in this class
        var afterDisable = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/customer.get");
        var enable = await admin.PutAsJsonAsync("/api/admin/operations/customer.get", new { isEnabled = true, concurrencyStamp = afterDisable.GetProperty("concurrencyStamp").GetString() });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
    }

    [Fact]
    public async Task Requests_already_executing_complete_with_the_configuration_they_started_with()
    {
        var admin = _factory.CreateAdminClient();
        var proxy = _factory.CreateProxyClient();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _factory.Upstream.Responder = async (_, ct) =>
        {
            await gate.Task.WaitAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        };

        try
        {
            var inFlight = proxy.ExecuteAsync(new { clientId = "report.get", json = new { urlId = "crm" } });
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (_factory.Upstream.Count == 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(10);
            }

            // Disable the operation while the upstream call is still running.
            var current = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/report.get");
            var disable = await admin.PutAsJsonAsync("/api/admin/operations/report.get", new { isEnabled = false, concurrencyStamp = current.GetProperty("concurrencyStamp").GetString() });
            Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

            gate.SetResult();
            Assert.Equal(HttpStatusCode.OK, (await inFlight).StatusCode); // not aborted mid-flight

            var next = await proxy.ExecuteAsync(new { clientId = "report.get", json = new { urlId = "crm" } });
            Assert.Equal(HttpStatusCode.Forbidden, next.StatusCode);      // new requests see the new configuration
            Assert.Equal(1, _factory.Upstream.Count);
        }
        finally
        {
            _factory.Upstream.Reset();
            var afterDisable = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/report.get");
            if (!afterDisable.GetProperty("isEnabled").GetBoolean())
            {
                await admin.PutAsJsonAsync("/api/admin/operations/report.get", new { isEnabled = true, concurrencyStamp = afterDisable.GetProperty("concurrencyStamp").GetString() });
            }
        }
    }

    [Fact]
    public async Task Invalid_configuration_changes_are_rejected()
    {
        var admin = _factory.CreateAdminClient();
        var current = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/order.create");
        var stamp = current.GetProperty("concurrencyStamp").GetString();

        var badMethod = await admin.PutAsJsonAsync("/api/admin/operations/order.create", new { httpMethod = "TRACE", concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.BadRequest, badMethod.StatusCode);

        var badTemplate = await admin.PutAsJsonAsync("/api/admin/operations/order.create", new { pathTemplate = "../{id}", concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.BadRequest, badTemplate.StatusCode);

        // order.create has body parameter rules: switching it to a body-less method would make every request fail validation.
        var bodylessMethod = await admin.PutAsJsonAsync("/api/admin/operations/order.create", new { httpMethod = "GET", concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.BadRequest, bodylessMethod.StatusCode);

        // A placeholder without a matching path parameter rule could never be bound, so the template is rejected up front.
        var orphanPlaceholder = await admin.PutAsJsonAsync("/api/admin/operations/order.create", new { pathTemplate = "orders/{orderId}", concurrencyStamp = stamp });
        Assert.Equal(HttpStatusCode.BadRequest, orphanPlaceholder.StatusCode);

        var unchanged = await admin.GetFromJsonAsync<JsonElement>("/api/admin/operations/order.create");
        Assert.Equal(stamp, unchanged.GetProperty("concurrencyStamp").GetString()); // failed changes never bump the stamp
    }

    [Fact]
    public async Task Admin_endpoints_require_the_api_key()
    {
        var anonymous = _factory.CreateClient();
        var response = await anonymous.GetAsync("/api/admin/operations");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var wrongKey = _factory.CreateClient();
        wrongKey.DefaultRequestHeaders.Add("X-Admin-ApiKey", "nope");
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrongKey.GetAsync("/api/admin/operations")).StatusCode);
    }

    [Fact]
    public async Task Secret_values_never_appear_in_admin_responses()
    {
        var admin = _factory.CreateAdminClient();
        var text = await admin.GetStringAsync("/api/admin/destinations/crm");

        Assert.Contains("cfg:crm-api-key", text);                    // the reference is configuration
        Assert.DoesNotContain(ProxyApiFactory.CrmUpstreamApiKey, text); // the value never leaves the secret source
    }
}

/// <summary>Without a configured admin key the admin surface must not exist at all.</summary>
public sealed class AdminDisabledFactory : ProxyApiFactory
{
    protected override IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?> { ["Admin:ApiKey"] = "" };
}

public sealed class AdminDisabledTests : IClassFixture<AdminDisabledFactory>
{
    private readonly AdminDisabledFactory _factory;

    public AdminDisabledTests(AdminDisabledFactory factory) => _factory = factory;

    [Fact]
    public async Task Admin_api_is_hidden_when_no_key_is_configured()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-ApiKey", ProxyApiFactory.AdminApiKey);

        var response = await client.GetAsync("/api/admin/operations");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
