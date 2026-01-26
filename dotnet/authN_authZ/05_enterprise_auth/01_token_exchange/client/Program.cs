using client.Saml;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);
var idpMetadataUrl = builder.Configuration["Saml:IdpMetadataUrl"]!;
var expectedIdpEntityId = builder.Configuration["Saml:ExpectedIdpEntityId"]!;
// Fetch metadata once at startup (simple, good for dev)
using (var http = new HttpClient())
{
    // If your localhost HTTPS trust is messy on macOS, fix dev cert trust rather than disabling validation.
    var metadataXml = http.GetStringAsync(idpMetadataUrl).GetAwaiter().GetResult();

    builder.Services.AddSingleton(new IdpMetadataCertStore(metadataXml, expectedIdpEntityId));
}
// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddSingleton(new SpOptions());
builder.Services.AddSingleton<AuthnRequestStore>();
// builder.Services.AddSingleton<IdpCertStore>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(opt =>
    {
        opt.LoginPath = "/saml/login";
        opt.Cookie.Name = "client.auth";
    });
builder.Services.AddAuthorization();
builder.Services.Configure<ApiJwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.AddSingleton<IApiTokenFactory, ApiTokenFactory>();

builder.Services.AddHttpClient("Api", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"]!);
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
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
