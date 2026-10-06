using System.Threading.RateLimiting;
using OtpService.Otp;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<OtpOptions>()
    .Bind(builder.Configuration.GetSection(OtpOptions.Section))
    .Validate(o => o.Secret.Length >= 32, "Otp:Secret debe tener al menos 32 caracteres.")
    .Validate(o => o.MaxAttempts > 0, "Otp:MaxAttempts debe ser mayor que 0.")
    .ValidateOnStart();

// En memoria para desarrollo. Para varias instancias usa Redis:
// builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "...");
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IOtpService, OtpService.Otp.OtpService>();

// Límite de peticiones por IP para frenar fuerza bruta
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("otp", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
});

var app = builder.Build();
app.UseRateLimiter();

var otp = app.MapGroup("/otp").RequireRateLimiting("otp");

otp.MapPost("/generate", async (GenerateOtpRequest req, IOtpService service, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(req.Subject) || string.IsNullOrWhiteSpace(req.Purpose))
        return Results.BadRequest(new { error = "Subject y Purpose son obligatorios." });

    var result = await service.GenerateAsync(req.Subject, req.Purpose, ct);

    // TODO: enviar result.Code por email/SMS aquí.
    // El código solo se devuelve en la respuesta en Development, para pruebas.
    return Results.Ok(new
    {
        result.ExpiresAt,
        Code = app.Environment.IsDevelopment() ? result.Code : null
    });
});

otp.MapPost("/validate", async (ValidateOtpRequest req, IOtpService service, CancellationToken ct) =>
{
    var result = await service.ValidateAsync(req.Subject, req.Purpose, req.Code, ct);

    return result == OtpValidationResult.Valid
        ? Results.Ok(new { valid = true })
        : Results.BadRequest(new { valid = false, reason = result.ToString() });
});

app.Run();

public sealed record GenerateOtpRequest(string Subject, string Purpose);
public sealed record ValidateOtpRequest(string Subject, string Purpose, string Code);
