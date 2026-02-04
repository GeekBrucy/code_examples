using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace _01_pgp_clear_sign.Services;

public interface ICertificateClearSignService
{
    Task GenerateCertificateAsync();
    Task<string> ClearSignAsync(string content);
    Task<bool> VerifySignatureAsync(string signedContent);
}

/// <summary>
/// Clear signing implementation using X.509 certificates (.pfx/.cer).
/// Server signs with .pfx (private key + cert), client verifies with .cer (public cert only).
/// </summary>
public class CertificateClearSignService : ICertificateClearSignService
{
    private readonly string _certsDirectory;
    private readonly string _pfxPath;      // Private key + certificate (server keeps this)
    private readonly string _cerPath;      // Public certificate only (share with clients)
    private readonly string _password;

    private const string SignedMessageHeader = "-----BEGIN CERTIFICATE SIGNED MESSAGE-----";
    private const string SignedMessageFooter = "-----END CERTIFICATE SIGNED MESSAGE-----";
    private const string SignatureHeader = "-----BEGIN CERTIFICATE SIGNATURE-----";
    private const string SignatureFooter = "-----END CERTIFICATE SIGNATURE-----";

    public CertificateClearSignService(IConfiguration configuration)
    {
        _certsDirectory = configuration["Certificate:CertsDirectory"] ?? "Certs";
        _pfxPath = Path.Combine(_certsDirectory, "signing.pfx");
        _cerPath = Path.Combine(_certsDirectory, "signing.cer");
        _password = configuration["Certificate:Password"] ?? "demo-password";
    }

    public async Task GenerateCertificateAsync()
    {
        if (File.Exists(_pfxPath) && File.Exists(_cerPath))
        {
            return;
        }

        Directory.CreateDirectory(_certsDirectory);

        // Generate a self-signed certificate
        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=Document Signing Certificate, O=Demo Organization",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add key usage extension (digital signature)
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        // Create self-signed certificate valid for 1 year
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddYears(1));

        // Export .pfx (private key + certificate) - server keeps this
        var pfxBytes = certificate.Export(X509ContentType.Pfx, _password);
        await File.WriteAllBytesAsync(_pfxPath, pfxBytes);

        // Export .cer (public certificate only) - share with clients
        var cerBytes = certificate.Export(X509ContentType.Cert);
        await File.WriteAllBytesAsync(_cerPath, cerBytes);
    }

    public async Task<string> ClearSignAsync(string content)
    {
        if (!File.Exists(_pfxPath))
        {
            await GenerateCertificateAsync();
        }

        // Load certificate with private key
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(_pfxPath, _password);
        using var rsa = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not contain RSA private key");

        // Sign the content
        var contentBytes = Encoding.UTF8.GetBytes(content);
        var signatureBytes = rsa.SignData(contentBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        // Format as clear-signed message
        var sb = new StringBuilder();
        sb.AppendLine(SignedMessageHeader);
        sb.AppendLine("Hash: SHA256");
        sb.AppendLine($"Certificate: {certificate.Subject}");
        sb.AppendLine($"Valid Until: {certificate.NotAfter:yyyy-MM-dd}");
        sb.AppendLine();
        sb.Append(content);
        if (!content.EndsWith('\n'))
        {
            sb.AppendLine();
        }
        sb.AppendLine(SignedMessageFooter);
        sb.AppendLine(SignatureHeader);

        // Wrap base64 at 64 characters
        for (int i = 0; i < signatureBase64.Length; i += 64)
        {
            sb.AppendLine(signatureBase64.Substring(i, Math.Min(64, signatureBase64.Length - i)));
        }

        sb.AppendLine(SignatureFooter);

        return sb.ToString();
    }

    public async Task<bool> VerifySignatureAsync(string signedContent)
    {
        if (!File.Exists(_cerPath))
        {
            return false;
        }

        try
        {
            var (content, signature) = ParseSignedContent(signedContent);
            if (content == null || signature == null)
            {
                return false;
            }

            // Load public certificate (no private key needed for verification)
            using var certificate = X509CertificateLoader.LoadCertificateFromFile(_cerPath);

            // Check certificate validity (NotBefore/NotAfter are in local time)
            var now = DateTime.Now;
            if (now < certificate.NotBefore || now > certificate.NotAfter)
            {
                return false; // Certificate expired or not yet valid
            }

            using var rsa = certificate.GetRSAPublicKey()
                ?? throw new InvalidOperationException("Certificate does not contain RSA public key");

            var contentBytes = Encoding.UTF8.GetBytes(content);
            var signatureBytes = Convert.FromBase64String(signature);

            return rsa.VerifyData(contentBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    private static (string? content, string? signature) ParseSignedContent(string signedContent)
    {
        var lines = signedContent.Split('\n').Select(l => l.TrimEnd('\r')).ToList();

        var contentStart = -1;
        var contentEnd = -1;
        var sigStart = -1;
        var sigEnd = -1;
        var foundEmptyLine = false;

        for (int i = 0; i < lines.Count; i++)
        {
            if (lines[i] == SignedMessageHeader)
            {
                // Content starts after the empty line following headers
                for (int j = i + 1; j < lines.Count; j++)
                {
                    if (string.IsNullOrEmpty(lines[j]) && !foundEmptyLine)
                    {
                        contentStart = j + 1;
                        foundEmptyLine = true;
                        break;
                    }
                }
            }
            else if (lines[i] == SignedMessageFooter)
            {
                contentEnd = i;
            }
            else if (lines[i] == SignatureHeader)
            {
                sigStart = i + 1;
            }
            else if (lines[i] == SignatureFooter)
            {
                sigEnd = i;
            }
        }

        if (contentStart < 0 || contentEnd < 0 || sigStart < 0 || sigEnd < 0)
        {
            return (null, null);
        }

        // Extract content
        var contentLines = lines.Skip(contentStart).Take(contentEnd - contentStart).ToList();
        while (contentLines.Count > 0 && string.IsNullOrEmpty(contentLines[^1]))
        {
            contentLines.RemoveAt(contentLines.Count - 1);
        }
        var content = string.Join("\n", contentLines);

        // Extract signature
        var signatureLines = lines.Skip(sigStart).Take(sigEnd - sigStart);
        var signature = string.Join("", signatureLines);

        return (content, signature);
    }
}
