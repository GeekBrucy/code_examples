using System.Security.Claims;
using ComponentSpace.Saml2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace client.ComponentSpace.Controllers;

[Route("[controller]")]
public class SamlController : Controller
{
    private readonly ISamlServiceProvider _samlServiceProvider;
    private readonly ILogger<SamlController> _logger;

    public SamlController(ISamlServiceProvider samlServiceProvider, ILogger<SamlController> logger)
    {
        _samlServiceProvider = samlServiceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Initiates SAML SSO by redirecting to the IdP.
    /// GET /saml/login
    /// </summary>
    [HttpGet("login")]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        // Store the return URL in relay state
        var relayState = returnUrl ?? "/";

        // Initiate SSO to the partner IdP (configured in appsettings.json)
        await _samlServiceProvider.InitiateSsoAsync(partnerName: null, relayState: relayState);

        // The above call will redirect the browser to the IdP
        return new EmptyResult();
    }

    /// <summary>
    /// Assertion Consumer Service - receives SAML Response from IdP.
    /// POST /saml/acs
    /// </summary>
    [HttpPost("acs")]
    public async Task<IActionResult> Acs()
    {
        // ComponentSpace handles all the SAML response validation:
        // - Signature verification
        // - Audience restriction
        // - Time conditions (NotBefore/NotOnOrAfter)
        // - InResponseTo correlation
        var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

        _logger.LogInformation(
            "SSO completed. User: {User}, Partner: {Partner}",
            ssoResult.UserID,
            ssoResult.PartnerName);

        // Build claims from SAML assertion
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, ssoResult.UserID),
            new(ClaimTypes.Name, ssoResult.UserID)
        };

        // Map SAML attributes to claims
        if (ssoResult.Attributes != null)
        {
            foreach (var attribute in ssoResult.Attributes)
            {
                var claimType = MapAttributeToClaimType(attribute.Name);

                foreach (var value in attribute.AttributeValues)
                {
                    var valueStr = value.ToString();
                    _logger.LogDebug("Adding claim: {Type}={Value}", claimType, valueStr);
                    claims.Add(new Claim(claimType, valueStr ?? string.Empty));
                }
            }
        }

        // Create the identity and sign in
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        // Redirect to the original URL (from relay state) or home
        var returnUrl = ssoResult.RelayState ?? "/";
        return LocalRedirect(returnUrl);
    }

    /// <summary>
    /// Logout endpoint - initiates SAML SLO or local logout.
    /// GET /saml/logout
    /// </summary>
    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        // Sign out locally
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Index", "Home");
    }

    private static string MapAttributeToClaimType(string attributeName)
    {
        return attributeName.ToLowerInvariant() switch
        {
            "email" => ClaimTypes.Email,
            "role" => ClaimTypes.Role,
            "given_name" or "givenname" => ClaimTypes.GivenName,
            "family_name" or "surname" => ClaimTypes.Surname,
            _ => attributeName
        };
    }
}
