namespace OtpService.Otp;

public interface IOtpService
{
    /// <summary>Genera un código de 6 dígitos para un sujeto (email, teléfono, id de usuario) y un propósito (login, reset-password...).</summary>
    Task<OtpCode> GenerateAsync(string subject, string purpose, CancellationToken ct = default);

    /// <summary>Valida el código. Si es correcto se consume (un solo uso).</summary>
    Task<OtpValidationResult> ValidateAsync(string subject, string purpose, string code, CancellationToken ct = default);
}

public sealed record OtpCode(string Code, DateTimeOffset ExpiresAt);

public enum OtpValidationResult
{
    Valid,
    Invalid,
    Expired,
    NotFound,
    TooManyAttempts
}
