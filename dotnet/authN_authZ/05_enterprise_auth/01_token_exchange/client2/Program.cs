using client2.Saml;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

var idpMetadataUrl = builder.Configuration["Saml:IdpMetadataUrl"]!;
var expectedIdpEntityId = builder.Configuration["Saml:ExpectedIdpEntityId"]!;

// Fetch IdP metadata at startup
using (var http = new HttpClient())
{
    var metadataXml = http.GetStringAsync(idpMetadataUrl).GetAwaiter().GetResult();
    builder.Services.AddSingleton(new IdpMetadataCertStore(metadataXml, expectedIdpEntityId));
}

builder.Services.AddControllersWithViews();
builder.Services.AddSingleton(new SpOptions());
builder.Services.AddSingleton<AuthnRequestStore>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(opt =>
    {
        opt.LoginPath = "/saml/login";
        opt.Cookie.Name = "client2.auth";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

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
