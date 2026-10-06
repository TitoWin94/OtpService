# OtpService

Servicio en .NET 10 para generar y validar códigos OTP de 6 dígitos.

## Ejecutar

```bash
dotnet user-secrets init
dotnet user-secrets set "Otp:Secret" "<clave-aleatoria-de-al-menos-32-caracteres>"
dotnet run
```

## Endpoints

- `POST /otp/generate` → `{ "subject": "usuario@correo.com", "purpose": "login" }`
- `POST /otp/validate` → `{ "subject": "usuario@correo.com", "purpose": "login", "code": "123456" }`

Ver `OtpService.http` para ejemplos.
