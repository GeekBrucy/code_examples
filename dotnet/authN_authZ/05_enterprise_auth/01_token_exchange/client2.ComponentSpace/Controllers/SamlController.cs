using System.Security.Claims;
using ComponentSpace.Saml2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace client2.ComponentSpace.Controllers;

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

    [HttpGet("login")]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        var relayState = returnUrl ?? "/";
        await _samlServiceProvider.InitiateSsoAsync(partnerName: null, relayState: relayState);
        return new EmptyResult();
    }

    [HttpPost("acs")]
    public async Task<IActionResult> Acs()
    {
        var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

        _logger.LogInformation("SSO completed. User: {User}, Partner: {Partner}",
            ssoResult.UserID, ssoResult.PartnerName);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, ssoResult.UserID),
            new(ClaimTypes.Name, ssoResult.UserID)
        };

        if (ssoResult.Attributes != null)
        {
            foreach (var attribute in ssoResult.Attributes)
            {
                var claimType = MapAttributeToClaimType(attribute.Name);
                foreach (var value in attribute.AttributeValues)
                {
                    claims.Add(new Claim(claimType, value.ToString() ?? string.Empty));
                }
            }
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return LocalRedirect(ssoResult.RelayState ?? "/");
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }

    private static string MapAttributeToClaimType(string attributeName) => attributeName.ToLowerInvariant() switch
    {
        "email" => ClaimTypes.Email,
        "role" => ClaimTypes.Role,
        "given_name" or "givenname" => ClaimTypes.GivenName,
        "family_name" or "surname" => ClaimTypes.Surname,
        _ => attributeName
    };
}
