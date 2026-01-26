using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using client2.Saml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace client2.Controllers;

[Route("[controller]")]
public class SamlController : Controller
{
    private readonly ILogger<SamlController> _logger;
    private readonly SpOptions _opt;
    private readonly IdpMetadataCertStore _idpCerts;
    private readonly AuthnRequestStore _requestStore;

    public SamlController(
        ILogger<SamlController> logger,
        SpOptions opt,
        IdpMetadataCertStore idpCerts,
        AuthnRequestStore requestStore)
    {
        _logger = logger;
        _opt = opt;
        _idpCerts = idpCerts;
        _requestStore = requestStore;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        var requestId = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        _requestStore.Add(requestId);
        var issueInstant = DateTime.UtcNow.ToString("o");

        var xml = $@"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
    ID=""{requestId}""
    Version=""2.0""
    IssueInstant=""{issueInstant}""
    Destination=""{_opt.IdpSsoUrl}""
    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
    AssertionConsumerServiceURL=""{_opt.AssertionConsumerServiceUrl}"">
  <saml:Issuer>{_opt.EntityId}</saml:Issuer>
</samlp:AuthnRequest>";

        var samlRequest = RedirectBindingEncoder.EncodeAuthnRequestForRedirect(xml);
        var relayState = Uri.EscapeDataString(requestId);
        var redirectUrl = $"{_opt.IdpSsoUrl}?SAMLRequest={samlRequest}&RelayState={relayState}";

        return Redirect(redirectUrl);
    }

    [HttpPost("acs")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Acs([FromForm] string? SAMLResponse, [FromForm] string? RelayState)
    {
        if (string.IsNullOrWhiteSpace(SAMLResponse))
            return BadRequest("Missing form field: SAMLResponse");

        var xmlBytes = Convert.FromBase64String(SAMLResponse);
        var xml = Encoding.UTF8.GetString(xmlBytes);

        _logger.LogInformation("Trusted IdP cert thumbprint = {Thumbprint}", _idpCerts.SigningCert.Thumbprint);

        var ok = XmlDsigVerifier.VerifyAssertionSignature(xml, _idpCerts.SigningCert);
        _logger.LogInformation("SAML Signature valid = {Valid}", ok);

        if (!ok) return Unauthorized("Invalid SAML Assertion signature.");

        var doc = XDocument.Parse(xml);
        XNamespace samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
        XNamespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";

        var response = doc.Root;
        if (response is null || response.Name != samlp + "Response")
            return BadRequest("Not a SAML2 Response.");

        var nameId = response
            .Descendants(saml + "Subject")
            .Descendants(saml + "NameID")
            .FirstOrDefault()
            ?.Value;

        if (string.IsNullOrWhiteSpace(nameId))
            return BadRequest("No NameID in SAML assertion.");

        var inResponseTo = response.Attribute("InResponseTo")?.Value;
        if (string.IsNullOrWhiteSpace(inResponseTo) ||
            !_requestStore.TryConsume(inResponseTo, TimeSpan.FromMinutes(5)))
            return Unauthorized($"Invalid or replayed SAML response (InResponseTo: {inResponseTo}).");

        var audience = doc.Descendants(saml + "Audience").FirstOrDefault()?.Value;
        if (!string.Equals(audience, _opt.EntityId, StringComparison.Ordinal))
            return Unauthorized("Invalid SAML audience.");

        var conditions = doc.Descendants(saml + "Conditions").FirstOrDefault();
        if (conditions is null)
            return Unauthorized("Missing Conditions.");

        var notBefore = DateTime.Parse(conditions.Attribute("NotBefore")!.Value).ToUniversalTime();
        var notOnOrAfter = DateTime.Parse(conditions.Attribute("NotOnOrAfter")!.Value).ToUniversalTime();

        var now = DateTime.UtcNow;
        var skew = TimeSpan.FromMinutes(2);
        if (now + skew < notBefore || now - skew >= notOnOrAfter)
            return Unauthorized("SAML assertion expired or not yet valid.");

        // Read attributes
        var attributes = doc.Descendants(saml + "Attribute")
            .Select(attr => new
            {
                Name = attr.Attribute("Name")?.Value,
                Values = attr.Elements(saml + "AttributeValue").Select(v => v.Value).ToList()
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .ToList();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, nameId),
            new(ClaimTypes.Name, nameId),
            new("relay_state", RelayState ?? "")
        };

        var email = attributes.FirstOrDefault(a => a.Name == "email")?.Values.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(email))
            claims.Add(new Claim(ClaimTypes.Email, email));

        var roles = attributes.FirstOrDefault(a => a.Name == "role")?.Values ?? new List<string>();
        foreach (var r in roles)
        {
            _logger.LogInformation("Role: {Role}", r);
            claims.Add(new Claim(ClaimTypes.Role, r));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return Redirect("/");
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }
}
