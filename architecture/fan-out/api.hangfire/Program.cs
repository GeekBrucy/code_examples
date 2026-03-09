using Hangfire;
using Hangfire.SqlServer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi();

// --- Hangfire setup ---
var connectionString = builder.Configuration.GetConnectionString("HangfireDb")
    ?? throw new InvalidOperationException("Connection string 'HangfireDb' not found.");

builder.Services.AddHangfire(config => config
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(connectionString, new SqlServerStorageOptions
    {
        CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
        SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
        QueuePollInterval = TimeSpan.Zero,          // react immediately to new jobs
        UseRecommendedIsolationLevel = true,
        DisableGlobalLocks = true
    }));

// Add the in-process background job server (the "worker" side)
// WorkerCount controls max parallelism for fan-out
builder.Services.AddHangfireServer(options =>
{
    options.WorkerCount = 10;   // up to 10 jobs running in parallel
    options.Queues = ["default"];
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthorization();

// Hangfire dashboard — browse to /hangfire to see all jobs, retries, succeeded/failed
app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    // Allow anonymous access in development; lock this down in production
    Authorization = []
});

app.MapControllers();

app.Run();
