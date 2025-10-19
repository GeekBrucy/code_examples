using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using API.Data;
using API.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Register DbContext with in-memory database for development
// In production, you would use a real database (SQL Server, PostgreSQL, etc.)
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseInMemoryDatabase("CertAuthDb"));

// Register services
builder.Services.AddSingleton<ICertificateValidationService, CertificateValidationService>();
builder.Services.AddScoped<IAuditService, AuditService>();

// Configure certificate authentication
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // Only accept chained certificates (not self-signed)
        // This ensures the certificate is part of a proper CA chain
        options.AllowedCertificateTypes = CertificateTypes.Chained;

        // Validate certificate use and validity period
        options.ValidateCertificateUse = true;
        options.ValidateValidityPeriod = true;

        // Custom validation event
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var validationService = context.HttpContext.RequestServices
                    .GetRequiredService<ICertificateValidationService>();

                var certificate = context.ClientCertificate;
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();

                logger.LogInformation(
                    "Validating certificate: Subject={Subject}, Issuer={Issuer}, Thumbprint={Thumbprint}",
                    certificate.Subject,
                    certificate.Issuer,
                    certificate.Thumbprint);

                // Perform custom validation against our local CA chain
                var validationResult = validationService.ValidateWithDetails(certificate);

                if (validationResult.IsValid)
                {
                    logger.LogInformation(
                        "Certificate validation successful for: {Subject}",
                        certificate.Subject);

                    // Set claims from certificate
                    var claims = new[]
                    {
                        new System.Security.Claims.Claim(
                            System.Security.Claims.ClaimTypes.Name,
                            certificate.Subject,
                            System.Security.Claims.ClaimValueTypes.String,
                            context.Options.ClaimsIssuer),
                        new System.Security.Claims.Claim(
                            System.Security.Claims.ClaimTypes.Thumbprint,
                            certificate.Thumbprint,
                            System.Security.Claims.ClaimValueTypes.Base64Binary,
                            context.Options.ClaimsIssuer)
                    };

                    context.Principal = new System.Security.Claims.ClaimsPrincipal(
                        new System.Security.Claims.ClaimsIdentity(claims, context.Scheme.Name));
                    context.Success();
                }
                else
                {
                    logger.LogWarning(
                        "Certificate validation failed for: {Subject}. Errors: {Errors}",
                        certificate.Subject,
                        string.Join(", ", validationResult.Errors));

                    context.Fail($"Certificate validation failed: {string.Join(", ", validationResult.Errors)}");
                }

                return Task.CompletedTask;
            },

            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<Program>>();

                logger.LogError(
                    context.Exception,
                    "Certificate authentication failed: {Message}",
                    context.Exception.Message);

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// Configure Kestrel to require client certificates
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(httpsOptions =>
    {
        // This makes client certificates optional - the authentication middleware will handle enforcement
        // Set to RequireCertificate to make it mandatory at the TLS level
        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Make the Program class accessible to integration tests
public partial class Program { }
