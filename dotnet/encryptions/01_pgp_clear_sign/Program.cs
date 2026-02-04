using _01_pgp_clear_sign.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<IPgpClearSignService, PgpClearSignService>();
builder.Services.AddSingleton<INativeClearSignService, NativeClearSignService>();
builder.Services.AddSingleton<ICertificateClearSignService, CertificateClearSignService>();

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Generate keys on startup if they don't exist
var pgpService = app.Services.GetRequiredService<IPgpClearSignService>();
await pgpService.GenerateKeyPairAsync();

var nativeService = app.Services.GetRequiredService<INativeClearSignService>();
await nativeService.GenerateKeyPairAsync();

var certService = app.Services.GetRequiredService<ICertificateClearSignService>();
await certService.GenerateCertificateAsync();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
