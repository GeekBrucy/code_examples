using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using client.Saml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace client.Controllers
{
    [Route("[controller]")]
    public class SamlController : Controller
    {
        private readonly ILogger<SamlController> _logger;
        private readonly SpOptions _opt;

        public SamlController(ILogger<SamlController> logger, SpOptions opt)
        {
            _logger = logger;
            _opt = opt;
        }
        // GET /saml/login  -> redirects browser to IdP with SAMLRequest
        [HttpGet("login")]
        public IActionResult Login()
        {
            var requestId = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var issueInstant = DateTime.UtcNow.ToString("o");

            // Minimal AuthnRequest (SP-initiated)
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

            // For now RelayState can just be the requestId (later you’ll correlate properly)
            var relayState = Uri.EscapeDataString(requestId);

            var redirectUrl = $"{_opt.IdpSsoUrl}?SAMLRequest={samlRequest}&RelayState={relayState}";
            return Redirect(redirectUrl);
        }


        // POST /saml/acs  <- receives SAMLResponse from IdP (we'll implement IdP POST next)
        [HttpPost("acs")]
        [IgnoreAntiforgeryToken] // important: IdP will POST, no antiforgery token
        public IActionResult Acs([FromForm] string? SAMLResponse, [FromForm] string? RelayState)
        {
            if (string.IsNullOrWhiteSpace(SAMLResponse))
                return BadRequest("Missing form field: SAMLResponse");

            // SAMLResponse in POST binding is usually base64(XML) (not compressed)
            var xmlBytes = Convert.FromBase64String(SAMLResponse);
            var xml = Encoding.UTF8.GetString(xmlBytes);

            // For now just display what came in (we’ll validate signature + sign-in cookie later)
            return Ok(new
            {
                RelayState,
                RawXml = xml
            });
        }
    }
}