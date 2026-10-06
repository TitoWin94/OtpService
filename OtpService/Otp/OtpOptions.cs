namespace OtpService.Otp;

public sealed class OtpOptions
{
    public const string Section = "Otp";

    /// <summary>Tiempo de vida del código.</summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Intentos fallidos permitidos antes de invalidar el código.</summary>
    public int MaxAttempts { get; set; } = 3;

    /// <summary>Clave secreta para el HMAC (mínimo 32 caracteres). Nunca la subas al repositorio.</summary>
    public string Secret { get; set; } = string.Empty;
}
