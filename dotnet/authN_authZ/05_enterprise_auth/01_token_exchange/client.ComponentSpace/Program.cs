using Microsoft.AspNetCore.Authentication.Cookies;
using ComponentSpace.Saml2.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configure Cookie Authentication (ComponentSpace uses this for session management)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Saml/Login";
        options.Cookie.Name = "client.componentspace.auth";
    });

builder.Services.AddAuthorization();

// Configure ComponentSpace SAML from appsettings
builder.Services.AddSaml(builder.Configuration.GetSection("Saml"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
