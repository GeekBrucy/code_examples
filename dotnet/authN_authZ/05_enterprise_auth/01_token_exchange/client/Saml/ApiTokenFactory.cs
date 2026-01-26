using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Client.Security;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace client.Saml
{
    public interface IApiTokenFactory
    {
        string CreateToken(ClaimsPrincipal user);
    }

    public sealed class ApiTokenFactory : IApiTokenFactory
    {
        private readonly ApiJwtOptions _opt;
        private readonly SigningCredentials _signing;

        public ApiTokenFactory(IOptions<ApiJwtOptions> opt, JwtSigningCertStore certs)
        {
            _opt = opt.Value;
            var rsaKey = new X509SecurityKey(certs.SigningCert);
            _signing = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        }

        public string CreateToken(ClaimsPrincipal user)
        {
            var now = DateTime.UtcNow;

            var sub = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.Identity?.Name ?? "unknown";

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, sub),
                new Claim("name", user.Identity?.Name ?? sub),
            };

            foreach (var role in user.FindAll(ClaimTypes.Role))
                claims.Add(new Claim("role", role.Value));

            var jwt = new JwtSecurityToken(
                issuer: _opt.Issuer,
                audience: _opt.Audience,
                claims: claims,
                notBefore: now,
                expires: now.AddMinutes(_opt.ExpiresMinutes),
                signingCredentials: _signing
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}