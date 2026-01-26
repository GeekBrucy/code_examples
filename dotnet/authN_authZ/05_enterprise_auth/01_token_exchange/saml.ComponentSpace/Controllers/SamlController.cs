using System.Security.Claims;
using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Assertions;
using ComponentSpace.Saml2.Metadata.Export;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace saml.ComponentSpace.Controllers;

[Route("[controller]")]
public class SamlController : Controller
{
    private readonly ISamlIdentityProvider _samlIdentityProvider;
    private readonly IConfigurationToMetadata _configurationToMetadata;
    private readonly ILogger<SamlController> _logger;

    public SamlController(
        ISamlIdentityProvider samlIdentityProvider,
        IConfigurationToMetadata configurationToMetadata,
        ILogger<SamlController> logger)
    {
        _samlIdentityProvider = samlIdentityProvider;
        _configurationToMetadata = configurationToMetadata;
        _logger = logger;
    }

    /// <summary>
    /// SSO endpoint - receives AuthnRequest from SP (HTTP-Redirect or HTTP-POST binding).
    /// GET/POST /saml/sso
    /// </summary>
    [HttpGet("sso")]
    [HttpPost("sso")]
    public async Task<IActionResult> Sso()
    {
        // Receive the SSO request from the SP
        var ssoResult = await _samlIdentityProvider.ReceiveSsoAsync();

        _logger.LogInformation(
            "SSO request received from partner: {Partner}",
            ssoResult.PartnerName);

        // Check if user is already authenticated
        if (User.Identity?.IsAuthenticated != true)
        {
            // Store the SSO state and redirect to login
            // ComponentSpace automatically manages the pending SSO state
            return RedirectToAction("Login");
        }

        // User is authenticated - send SAML response
        return await SendSsoResponseAsync();
    }

    /// <summary>
    /// Login page for the IdP.
    /// GET /saml/login
    /// </summary>
    [HttpGet("login")]
    public IActionResult Login()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Sso");
        }

        return View();
    }

    /// <summary>
    /// Process login form submission.
    /// POST /saml/login
    /// </summary>
    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string username, string password)
    {
        // For dev purposes: accept any username with password "password"
        // In production, validate against your user store
        if (string.IsNullOrWhiteSpace(username) || password != "password")
        {
            ViewBag.Error = "Invalid credentials. Use any username with password 'password'.";
            return View();
        }

        // Create claims for the authenticated user
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, username),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Email, $"{username}@example.com"),
            new(ClaimTypes.GivenName, "Demo"),
            new(ClaimTypes.Surname, "User"),
            new(ClaimTypes.Role, "Admin"),
            new(ClaimTypes.Role, "Reader")
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        _logger.LogInformation("User {Username} logged in", username);

        // Check if there's a pending SSO request
        var status = await _samlIdentityProvider.GetStatusAsync();
        if (status.IsSsoCompletionPending())
        {
            return await SendSsoResponseAsync();
        }

        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Logout endpoint.
    /// GET /saml/logout
    /// </summary>
    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Metadata endpoint - returns IdP SAML metadata.
    /// GET /saml/metadata
    /// </summary>
    [HttpGet("metadata")]
    public async Task<IActionResult> Metadata()
    {
        var entityDescriptor = await _configurationToMetadata.ExportAsync();
        var metadata = entityDescriptor.ToXml().OuterXml;
        return Content(metadata, "application/xml");
    }

    /// <summary>
    /// Send SAML response back to the SP.
    /// </summary>
    private async Task<IActionResult> SendSsoResponseAsync()
    {
        var userName = User.Identity?.Name ?? "unknown";

        // Build SAML attributes from user claims
        var attributes = new List<SamlAttribute>();

        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        if (!string.IsNullOrEmpty(email))
        {
            attributes.Add(new SamlAttribute("email", email));
        }

        var givenName = User.FindFirst(ClaimTypes.GivenName)?.Value;
        if (!string.IsNullOrEmpty(givenName))
        {
            attributes.Add(new SamlAttribute("given_name", givenName));
        }

        var surname = User.FindFirst(ClaimTypes.Surname)?.Value;
        if (!string.IsNullOrEmpty(surname))
        {
            attributes.Add(new SamlAttribute("family_name", surname));
        }

        // Add all role claims - each role as a separate attribute with same name
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        foreach (var role in roles)
        {
            attributes.Add(new SamlAttribute("role", role));
        }

        _logger.LogInformation(
            "Sending SSO response for user: {User} with {AttributeCount} attributes",
            userName,
            attributes.Count);

        // Send SAML response to the SP
        await _samlIdentityProvider.SendSsoAsync(userName, attributes);

        return new EmptyResult();
    }
}
