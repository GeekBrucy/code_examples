using System.Diagnostics;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using saml.Saml;

namespace saml.Controllers
{
    [Route("[controller]")]
    public class SamlController : Controller
    {
        private readonly ILogger<SamlController> _logger;
        private readonly IdpOptions _opt;
        private readonly CertStore _certs;

        public SamlController(ILogger<SamlController> logger, IdpOptions opt, CertStore certs)
        {
            _logger = logger;
            _opt = opt;
            _certs = certs;
        }

        [HttpGet("metadata")]
        public IActionResult Metadata()
        {
            // public cert only (no private key)
            var certBase64 = Convert.ToBase64String(_certs.SigningCert.RawData);

            var xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
                  entityID=""{_opt.EntityId}"">
  <IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""
                   WantAuthnRequestsSigned=""false"">

    <KeyDescriptor use=""signing"">
      <ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
        <ds:X509Data>
          <ds:X509Certificate>{certBase64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>

    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>

    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
                         Location=""{_opt.SingleSignOnServiceUrl}"" />

    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
                         Location=""{_opt.SingleSignOnServiceUrl}"" />
  </IDPSSODescriptor>
</EntityDescriptor>
";

            // If you prefer browser display:
            return Content(xml, "application/xml", Encoding.UTF8);
        }

        // GET /saml/sso (stub for now)
        [HttpGet("sso")]
        public IActionResult Sso()
        {
            // Next step we’ll parse SAMLRequest + RelayState.
            return Ok("SSO endpoint is up. Next: parse SAMLRequest.");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View("Error!");
        }
    }
}