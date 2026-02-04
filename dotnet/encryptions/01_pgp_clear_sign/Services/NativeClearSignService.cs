using System.Security.Cryptography;
using System.Text;

namespace _01_pgp_clear_sign.Services;

public interface INativeClearSignService
{
    Task GenerateKeyPairAsync();
    Task<string> ClearSignAsync(string content);
    Task<bool> VerifySignatureAsync(string signedContent);
}

/// <summary>
/// Clear signing implementation using only .NET built-in cryptography.
/// Uses RSA with SHA256 - no third-party libraries required.
/// </summary>
public class NativeClearSignService : INativeClearSignService
{
    private readonly string _keysDirectory;
    private readonly string _privateKeyPath;
    private readonly string _publicKeyPath;

    private const string SignedMessageHeader = "-----BEGIN SIGNED MESSAGE-----";
    private const string SignedMessageFooter = "-----END SIGNED MESSAGE-----";
    private const string SignatureHeader = "-----BEGIN RSA SIGNATURE-----";
    private const string SignatureFooter = "-----END RSA SIGNATURE-----";

    public NativeClearSignService(IConfiguration configuration)
    {
        _keysDirectory = configuration["Native:KeysDirectory"] ?? "NativeKeys";
        _privateKeyPath = Path.Combine(_keysDirectory, "private.pem");
        _publicKeyPath = Path.Combine(_keysDirectory, "public.pem");
    }

    public async Task GenerateKeyPairAsync()
    {
        if (File.Exists(_privateKeyPath) && File.Exists(_publicKeyPath))
        {
            return;
        }

        Directory.CreateDirectory(_keysDirectory);

        using var rsa = RSA.Create(2048);

        // Export private key in PEM format
        var privateKey = rsa.ExportRSAPrivateKeyPem();
        await File.WriteAllTextAsync(_privateKeyPath, privateKey);

        // Export public key in PEM format
        var publicKey = rsa.ExportRSAPublicKeyPem();
        await File.WriteAllTextAsync(_publicKeyPath, publicKey);
    }

    public async Task<string> ClearSignAsync(string content)
    {
        if (!File.Exists(_privateKeyPath))
        {
            await GenerateKeyPairAsync();
        }

        var privateKeyPem = await File.ReadAllTextAsync(_privateKeyPath);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);

        // Sign the content
        var contentBytes = Encoding.UTF8.GetBytes(content);
        var signatureBytes = rsa.SignData(contentBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        // Format as clear-signed message
        var sb = new StringBuilder();
        sb.AppendLine(SignedMessageHeader);
        sb.AppendLine("Hash: SHA256");
        sb.AppendLine();
        sb.Append(content);
        if (!content.EndsWith('\n'))
        {
            sb.AppendLine();
        }
        sb.AppendLine(SignedMessageFooter);
        sb.AppendLine(SignatureHeader);

        // Wrap base64 at 64 characters (standard PEM style)
        for (int i = 0; i < signatureBase64.Length; i += 64)
        {
            sb.AppendLine(signatureBase64.Substring(i, Math.Min(64, signatureBase64.Length - i)));
        }

        sb.AppendLine(SignatureFooter);

        return sb.ToString();
    }

    public async Task<bool> VerifySignatureAsync(string signedContent)
    {
        if (!File.Exists(_publicKeyPath))
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

            var publicKeyPem = await File.ReadAllTextAsync(_publicKeyPath);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);

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

        // Find content section
        var contentStart = -1;
        var contentEnd = -1;
        var sigStart = -1;
        var sigEnd = -1;

        for (int i = 0; i < lines.Count; i++)
        {
            if (lines[i] == SignedMessageHeader)
            {
                // Skip header and "Hash:" line and blank line
                contentStart = i + 3;
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

        // Extract content (remove trailing empty lines)
        var contentLines = lines.Skip(contentStart).Take(contentEnd - contentStart).ToList();
        while (contentLines.Count > 0 && string.IsNullOrEmpty(contentLines[^1]))
        {
            contentLines.RemoveAt(contentLines.Count - 1);
        }
        var content = string.Join("\n", contentLines);

        // Extract signature (join all base64 lines)
        var signatureLines = lines.Skip(sigStart).Take(sigEnd - sigStart);
        var signature = string.Join("", signatureLines);

        return (content, signature);
    }
}
