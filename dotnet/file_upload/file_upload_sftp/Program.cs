using System.Text;
using file_upload_sftp.Data;
using file_upload_sftp.Models;
using file_upload_sftp.Services;
using file_upload_sftp.Settings;
using Hangfire;
using Hangfire.InMemory;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Configuration
builder.Services.Configure<SftpOptions>(builder.Configuration.GetSection("Sftp"));
builder.Services.Configure<OutboxOptions>(builder.Configuration.GetSection("Outbox"));

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("App") ?? "Data Source=app.db"));

// Hangfire (in-memory for demo — use SQL Server/PostgreSQL in production)
builder.Services.AddHangfire(config => config
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseInMemoryStorage());
builder.Services.AddHangfireServer();

// Services
builder.Services.AddScoped<IDistributionService, DistributionService>();
builder.Services.AddScoped<ISftpDeliveryService, SftpDeliveryService>();
builder.Services.AddScoped<OutboxProcessor>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

// Ensure database is created + seed demo data
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    SeedDemoData(db);
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthorization();

// Hangfire dashboard (dev only — gives visibility into jobs)
if (app.Environment.IsDevelopment())
{
    app.UseHangfireDashboard("/hangfire");
}

app.MapControllers();

// Recurring safety-net sweep — runs every minute, catches retries and missed entries
RecurringJob.AddOrUpdate<OutboxProcessor>(
    "outbox-sweep",
    p => p.SweepPendingEntries(),
    "* * * * *"); // every minute

// Daily self-healing — resets Failed entries for another round of attempts (up to MaxResets times)
RecurringJob.AddOrUpdate<OutboxProcessor>(
    "outbox-daily-reset",
    p => p.ResetFailedEntries(),
    "0 6 * * *"); // 6 AM daily

app.Run();

// --- Demo seed data (represents what already exists in the real system) ---
static void SeedDemoData(AppDbContext db)
{
    if (db.ExternalUsers.Any()) return;

    // External users (map to SFTP directories)
    var partnerA = new ExternalUser { Name = "Partner A Corp", SftpDirectory = "partnerA" };
    var partnerB = new ExternalUser { Name = "Partner B Ltd", SftpDirectory = "partnerB" };
    db.ExternalUsers.AddRange(partnerA, partnerB);
    db.SaveChanges();

    // A submitted report with referrals and attachments
    var report1 = new Report
    {
        Title = "Annual Compliance Report 2025",
        Status = "Submitted",
        JsonContent = """{"reportType":"compliance","year":2025,"findings":[{"id":1,"severity":"low","description":"Minor documentation gap"}]}""",
        Referrals =
        [
            new ReportReferral { ExternalUser = partnerA },
            new ReportReferral { ExternalUser = partnerB }
        ],
        Attachments =
        [
            new ReportAttachment
            {
                FileName = "findings_summary.csv",
                ContentType = "text/csv",
                Content = Encoding.UTF8.GetBytes("id,severity,description\n1,low,Minor documentation gap\n")
            },
            new ReportAttachment
            {
                FileName = "evidence.pdf",
                ContentType = "application/pdf",
                Content = Encoding.UTF8.GetBytes("%PDF-1.4 (demo placeholder content)")
            }
        ]
    };

    // Another report referred only to partner A
    var report2 = new Report
    {
        Title = "Q4 Financial Summary",
        Status = "Submitted",
        JsonContent = """{"reportType":"financial","quarter":"Q4","totalAmount":150000.00}""",
        Referrals =
        [
            new ReportReferral { ExternalUser = partnerA }
        ],
        Attachments =
        [
            new ReportAttachment
            {
                FileName = "transactions.json",
                ContentType = "application/json",
                Content = Encoding.UTF8.GetBytes("""[{"id":1,"amount":50000},{"id":2,"amount":100000}]""")
            }
        ]
    };

    db.Reports.AddRange(report1, report2);
    db.SaveChanges();
}
