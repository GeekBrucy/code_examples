using file_upload_sftp_consumer.Services;
using file_upload_sftp_consumer.Settings;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<SftpHostOptions>(builder.Configuration.GetSection("Sftp"));

// Build partner credentials dictionary from config
var partnersSection = builder.Configuration.GetSection("Partners");
var partners = new Dictionary<string, PartnerCredentials>();
foreach (var child in partnersSection.GetChildren())
{
    partners[child.Key] = new PartnerCredentials
    {
        Username = child["Username"]!,
        Password = child["Password"]!
    };
}
builder.Services.AddSingleton<IReadOnlyDictionary<string, PartnerCredentials>>(partners);

builder.Services.AddSingleton<ISftpBrowserService, SftpBrowserService>();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();
app.MapControllers();

app.Run();
