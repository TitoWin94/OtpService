using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace OtpService.Otp;

public sealed class OtpService(
    IDistributedCache cache,
    IOptions<OtpOptions> options,
    TimeProvider time) : IOtpService
{
    private const int Digits = 6;
    private readonly OtpOptions _opt = options.Value;
    private readonly byte[] _secret = Encoding.UTF8.GetBytes(options.Value.Secret);

    public async Task<OtpCode> GenerateAsync(string subject, string purpose, CancellationToken ct = default)
    {
        // Generador criptográficamente seguro, rango 000000-999999
        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var expiresAt = time.GetUtcNow().Add(_opt.Expiration);

        // Solo se guarda el hash, nunca el código en claro.
        // Generar un código nuevo reemplaza al anterior.
        var entry = new OtpEntry(Hash(subject, purpose, code), 0, expiresAt);
        await SaveAsync(Key(subject, purpose), entry, ct);

        return new OtpCode(code, expiresAt);
    }

    public async Task<OtpValidationResult> ValidateAsync(string subject, string purpose, string code, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(code) || code.Length != Digits || !code.All(char.IsAsciiDigit))
            return OtpValidationResult.Invalid;

        var key = Key(subject, purpose);
        var bytes = await cache.GetAsync(key, ct);
        if (bytes is null)
            return OtpValidationResult.NotFound;

        var entry = JsonSerializer.Deserialize<OtpEntry>(bytes)!;

        if (entry.ExpiresAt <= time.GetUtcNow())
        {
            await cache.RemoveAsync(key, ct);
            return OtpValidationResult.Expired;
        }

        // Comparación en tiempo constante para evitar ataques de temporización
        var hash = Hash(subject, purpose, code);
        if (CryptographicOperations.FixedTimeEquals(hash, entry.Hash))
        {
            await cache.RemoveAsync(key, ct); // un solo uso
            return OtpValidationResult.Valid;
        }

        var attempts = entry.Attempts + 1;
        if (attempts >= _opt.MaxAttempts)
        {
            await cache.RemoveAsync(key, ct);
            return OtpValidationResult.TooManyAttempts;
        }

        await SaveAsync(key, entry with { Attempts = attempts }, ct);
        return OtpValidationResult.Invalid;
    }

    private Task SaveAsync(string key, OtpEntry entry, CancellationToken ct) =>
        cache.SetAsync(
            key,
            JsonSerializer.SerializeToUtf8Bytes(entry),
            new DistributedCacheEntryOptions { AbsoluteExpiration = entry.ExpiresAt },
            ct);

    private byte[] Hash(string subject, string purpose, string code) =>
        HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes($"{purpose}|{subject}|{code}"));

    private static string Key(string subject, string purpose) =>
        $"otp:{purpose}:{subject.Trim().ToLowerInvariant()}";

    private sealed record OtpEntry(byte[] Hash, int Attempts, DateTimeOffset ExpiresAt);
}
