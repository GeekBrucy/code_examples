using Api.Filters;
using Api.Services;
using Api.Settings;
using Hangfire;
using Hangfire.InMemory;

var builder = WebApplication.CreateBuilder(args);

// ── Settings ─────────────────────────────────────────────────────────────────
builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings"));

// ── Application services ──────────────────────────────────────────────────────
builder.Services.AddScoped<INotificationService, ConsoleNotificationService>();

// ── Hangfire ──────────────────────────────────────────────────────────────────
builder.Services.AddHangfire(config =>
    config.UseInMemoryStorage());

builder.Services.AddHangfireServer();

// ── ASP.NET ───────────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

// ── Hangfire global filters ───────────────────────────────────────────────────
// Registered after the DI container is built so we can resolve IServiceScopeFactory.
GlobalJobFilters.Filters.Add(
    new NotifyOnFailureFilter(app.Services.GetRequiredService<IServiceScopeFactory>()));

// ── Middleware ────────────────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseHangfireDashboard(); // available at /hangfire
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
