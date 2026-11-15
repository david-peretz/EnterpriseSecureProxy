using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;
using SecureProxy.Api.Security;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests.Unit;

public sealed class AesGcmPayloadDecryptorTests
{
    private static readonly byte[] Key = Convert.FromBase64String(TestSeed.TestKeyBase64);

    private static readonly EncryptionProfile Profile = new()
    {
        Id = Guid.NewGuid(), Key = "p1", Algorithm = EncryptionAlgorithms.Aes256Gcm, KeyReference = "cfg:k1", KeyVersion = 1, IsEnabled = true
    };

    private static AesGcmPayloadDecryptor Decryptor(string? keyBase64 = TestSeed.TestKeyBase64)
    {
        var values = new Dictionary<string, string?>();
        if (keyBase64 is not null)
        {
            values["Secrets:k1"] = keyBase64;
        }

        return new AesGcmPayloadDecryptor(new ConfigurationSecretSource(new ConfigurationBuilder().AddInMemoryCollection(values).Build()));
    }

    private static EncryptedPayload Payload(object encrypted)
    {
        var node = (System.Text.Json.Nodes.JsonObject)encrypted;
        return new EncryptedPayload(node["nonce"]!.GetValue<string>(), node["ciphertext"]!.GetValue<string>(), node["tag"]!.GetValue<string>(), node["keyVersion"]?.GetValue<int>());
    }

    [Fact]
    public async Task Round_trips_a_payload_bound_to_the_operation_key()
    {
        var plaintext = Encoding.UTF8.GetBytes("""{"a":1}""");
        var result = await Decryptor().DecryptAsync(Profile, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a")), CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(plaintext, result.Plaintext);
    }

    [Fact]
    public async Task Classifies_failures_without_ever_returning_plaintext()
    {
        var plaintext = Encoding.UTF8.GetBytes("""{"a":1}""");

        var tampered = await Decryptor().DecryptAsync(Profile, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a", tamperTag: t => t[3] ^= 1)), CancellationToken.None);
        Assert.Equal(DecryptionFailure.AuthenticationFailed, tampered.Failure);
        Assert.Null(tampered.Plaintext);

        var otherOperation = await Decryptor().DecryptAsync(Profile, "op.b", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a")), CancellationToken.None);
        Assert.Equal(DecryptionFailure.AuthenticationFailed, otherOperation.Failure);

        var noKey = await Decryptor(keyBase64: null).DecryptAsync(Profile, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a")), CancellationToken.None);
        Assert.Equal(DecryptionFailure.KeyUnavailable, noKey.Failure);

        var shortKey = await Decryptor(keyBase64: Convert.ToBase64String(new byte[16])).DecryptAsync(Profile, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a")), CancellationToken.None);
        Assert.Equal(DecryptionFailure.KeyUnavailable, shortKey.Failure);

        var wrongVersion = await Decryptor().DecryptAsync(Profile, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a", keyVersion: 9)), CancellationToken.None);
        Assert.Equal(DecryptionFailure.KeyVersionMismatch, wrongVersion.Failure);

        var disabled = await Decryptor().DecryptAsync(new EncryptionProfile { Key = "p", Algorithm = EncryptionAlgorithms.Aes256Gcm, KeyReference = "cfg:k1", IsEnabled = false }, "op.a", Payload(AesGcmTestHelper.EncryptBytes(plaintext, Key, "op.a")), CancellationToken.None);
        Assert.Equal(DecryptionFailure.ProfileDisabled, disabled.Failure);

        var malformed = await Decryptor().DecryptAsync(Profile, "op.a", new EncryptedPayload("AAAA", "AAAA", "AAAA", 1), CancellationToken.None);
        Assert.Equal(DecryptionFailure.MalformedInput, malformed.Failure);
    }
}

public sealed class ConfigurationSecretSourceTests
{
    [Fact]
    public async Task Resolves_only_well_formed_references()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Secrets:api-key"] = "plain-value",
            ["Secrets:key-material"] = Convert.ToBase64String(new byte[32]),
            ["Secrets:not-base64"] = "***",
            ["ConnectionStrings:ProxyDb"] = "should-not-be-reachable"
        }).Build();
        var source = new ConfigurationSecretSource(configuration);

        Assert.Equal("plain-value", await source.GetSecretStringAsync("cfg:api-key", CancellationToken.None));
        Assert.Equal(32, (await source.GetSecretBytesAsync("cfg:key-material", CancellationToken.None))!.Length);
        Assert.Null(await source.GetSecretBytesAsync("cfg:not-base64", CancellationToken.None));
        Assert.Null(await source.GetSecretStringAsync("cfg:missing", CancellationToken.None));
        Assert.Null(await source.GetSecretStringAsync("ConnectionStrings:ProxyDb", CancellationToken.None)); // no prefix: not a secret reference
        Assert.Null(await source.GetSecretStringAsync("cfg:../ConnectionStrings:ProxyDb", CancellationToken.None)); // no traversal into other sections
    }
}

public sealed class DestinationCircuitBreakerTests
{
    private sealed class ManualTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static DestinationCircuitBreaker Create(ManualTimeProvider time, int threshold = 2, int breakSeconds = 30)
    {
        var options = new ResilienceOptions { CircuitBreakerFailureThreshold = threshold, CircuitBreakerBreakSeconds = breakSeconds };
        return new DestinationCircuitBreaker(new StaticOptionsMonitor<ResilienceOptions>(options), time, NullLogger<DestinationCircuitBreaker>.Instance);
    }

    [Fact]
    public void Opens_after_threshold_half_opens_after_break_and_closes_on_success()
    {
        var time = new ManualTimeProvider();
        var breaker = Create(time);
        var destination = Guid.NewGuid();

        breaker.RecordFailure(destination);
        Assert.True(breaker.TryEnter(destination));
        breaker.RecordFailure(destination);
        Assert.False(breaker.TryEnter(destination));

        time.Now += TimeSpan.FromSeconds(31);
        Assert.True(breaker.TryEnter(destination));   // single probe allowed
        Assert.False(breaker.TryEnter(destination));  // everyone else still rejected while the probe is in flight

        breaker.RecordSuccess(destination);
        Assert.True(breaker.TryEnter(destination));
        Assert.True(breaker.TryEnter(destination));
    }

    [Fact]
    public void Failed_probe_reopens_the_circuit_and_failures_are_per_destination()
    {
        var time = new ManualTimeProvider();
        var breaker = Create(time);
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();

        breaker.RecordFailure(a);
        breaker.RecordFailure(a);
        Assert.False(breaker.TryEnter(a));
        Assert.True(breaker.TryEnter(b));

        time.Now += TimeSpan.FromSeconds(31);
        Assert.True(breaker.TryEnter(a));
        breaker.RecordFailure(a);
        Assert.False(breaker.TryEnter(a));
    }

    [Fact]
    public void Released_or_lost_probe_never_latches_the_circuit_open()
    {
        var time = new ManualTimeProvider();
        var breaker = Create(time);
        var destination = Guid.NewGuid();
        breaker.RecordFailure(destination);
        breaker.RecordFailure(destination);

        // Probe admitted, then the caller disappears without a verdict → Release frees the slot immediately.
        time.Now += TimeSpan.FromSeconds(31);
        Assert.True(breaker.TryEnter(destination));
        Assert.False(breaker.TryEnter(destination));
        breaker.Release(destination);
        Assert.True(breaker.TryEnter(destination));

        // A probe that is never reported back expires after the break period instead of blocking forever.
        Assert.False(breaker.TryEnter(destination));
        time.Now += TimeSpan.FromSeconds(31);
        Assert.True(breaker.TryEnter(destination));
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
