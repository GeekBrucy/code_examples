using file_upload_sftp.Data;
using file_upload_sftp.Services;
using file_upload_sftp.Settings;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Configuration
builder.Services.Configure<SftpOptions>(builder.Configuration.GetSection("Sftp"));
builder.Services.Configure<OutboxOptions>(builder.Configuration.GetSection("Outbox"));

// Database
builder.Services.AddDbContext<OutboxDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Outbox") ?? "Data Source=outbox.db"));

// Services
builder.Services.AddSingleton<ISftpService, SftpService>();
builder.Services.AddScoped<IDistributionService, DistributionService>();
builder.Services.AddScoped<ISftpDeliveryService, SftpDeliveryService>();
builder.Services.AddHostedService<OutboxProcessor>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<OutboxDbContext>();
    db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
