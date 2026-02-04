using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System.Text;

namespace _01_pgp_clear_sign.Services;

public interface IPgpClearSignService
{
    Task<string> ClearSignAsync(string content);
    Task<bool> VerifySignatureAsync(string signedContent);
    Task GenerateKeyPairAsync();
}

public class PgpClearSignService : IPgpClearSignService
{
    private readonly string _keysDirectory;
    private readonly string _privateKeyPath;
    private readonly string _publicKeyPath;
    private readonly string _passphrase;

    public PgpClearSignService(IConfiguration configuration)
    {
        _keysDirectory = configuration["Pgp:KeysDirectory"] ?? "Keys";
        _privateKeyPath = Path.Combine(_keysDirectory, "private.asc");
        _publicKeyPath = Path.Combine(_keysDirectory, "public.asc");
        _passphrase = configuration["Pgp:Passphrase"] ?? "demo-passphrase";
    }

    public async Task GenerateKeyPairAsync()
    {
        // Skip if keys already exist
        if (File.Exists(_privateKeyPath) && File.Exists(_publicKeyPath))
        {
            return;
        }

        Directory.CreateDirectory(_keysDirectory);

        var keyRingGenerator = GenerateKeyRingGenerator("demo@example.com", _passphrase.ToCharArray());

        // Export private key
        var secretKeyRing = keyRingGenerator.GenerateSecretKeyRing();
        await using (var privateOut = File.Create(_privateKeyPath))
        await using (var armoredOut = new ArmoredOutputStream(privateOut))
        {
            secretKeyRing.Encode(armoredOut);
        }

        // Export public key
        var publicKeyRing = keyRingGenerator.GeneratePublicKeyRing();
        await using (var publicOut = File.Create(_publicKeyPath))
        await using (var armoredOut = new ArmoredOutputStream(publicOut))
        {
            publicKeyRing.Encode(armoredOut);
        }
    }

    public async Task<string> ClearSignAsync(string content)
    {
        if (!File.Exists(_privateKeyPath))
        {
            await GenerateKeyPairAsync();
        }

        var (secretKey, privateKey) = await ReadSecretAndPrivateKeyAsync();

        using var outputStream = new MemoryStream();

        // Create the signature generator
        var signatureGenerator = new PgpSignatureGenerator(
            secretKey.PublicKey.Algorithm,
            HashAlgorithmTag.Sha256);
        signatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, privateKey);

        await using (var armoredOut = new ArmoredOutputStream(outputStream))
        {
            armoredOut.BeginClearText(HashAlgorithmTag.Sha256);

            // Split content into lines and process
            var lines = content.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                var processedLine = ProcessLine(line);
                var lineBytes = Encoding.UTF8.GetBytes(processedLine);

                // Write to output
                if (i > 0)
                {
                    armoredOut.WriteByte((byte)'\r');
                    armoredOut.WriteByte((byte)'\n');
                }
                armoredOut.Write(lineBytes, 0, lineBytes.Length);

                // Update signature (with CRLF between lines)
                if (i > 0)
                {
                    signatureGenerator.Update((byte)'\r');
                    signatureGenerator.Update((byte)'\n');
                }
                foreach (var b in lineBytes)
                {
                    signatureGenerator.Update(b);
                }
            }

            // Add a trailing newline before ending clear text
            armoredOut.WriteByte((byte)'\r');
            armoredOut.WriteByte((byte)'\n');

            armoredOut.EndClearText();

            // Generate and encode signature
            var signature = signatureGenerator.Generate();
            signature.Encode(armoredOut);
        }

        return Encoding.UTF8.GetString(outputStream.ToArray());
    }

    public async Task<bool> VerifySignatureAsync(string signedContent)
    {
        if (!File.Exists(_publicKeyPath))
        {
            return false;
        }

        try
        {
            var publicKey = await ReadPublicKeyAsync();

            using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(signedContent));
            using var armoredIn = new ArmoredInputStream(inputStream);

            // Read lines from clear text
            var linesList = new List<byte[]>();
            var currentLine = new MemoryStream();

            while (armoredIn.IsClearText())
            {
                var b = armoredIn.ReadByte();
                if (b < 0) break;

                if (b == '\r')
                {
                    continue; // Skip CR, we'll handle at LF
                }

                if (b == '\n')
                {
                    linesList.Add(currentLine.ToArray());
                    currentLine = new MemoryStream();
                }
                else
                {
                    currentLine.WriteByte((byte)b);
                }
            }

            // Add last line
            if (currentLine.Length > 0)
            {
                linesList.Add(currentLine.ToArray());
            }

            // Remove trailing empty lines and lines that are part of the signature delimiter
            while (linesList.Count > 0)
            {
                var lastLine = linesList[^1];
                var isEmpty = lastLine.Length == 0;
                var startsWithDash = lastLine.Length > 0 && lastLine[0] == (byte)'-';
                if (isEmpty || startsWithDash)
                {
                    linesList.RemoveAt(linesList.Count - 1);
                }
                else
                {
                    break;
                }
            }

            // Read signature
            var pgpObjectFactory = new PgpObjectFactory(armoredIn);
            var pgpObject = pgpObjectFactory.NextPgpObject();

            if (pgpObject == null)
            {
                return false;
            }

            var signatureList = (PgpSignatureList)pgpObject;
            var signature = signatureList[0];

            signature.InitVerify(publicKey);

            // Process each line for verification
            for (int i = 0; i < linesList.Count; i++)
            {
                if (i > 0)
                {
                    signature.Update((byte)'\r');
                    signature.Update((byte)'\n');
                }

                var lineStr = Encoding.UTF8.GetString(linesList[i]);
                var processedLine = ProcessLine(lineStr);
                var processedBytes = Encoding.UTF8.GetBytes(processedLine);

                foreach (var b in processedBytes)
                {
                    signature.Update(b);
                }
            }

            return signature.Verify();
        }
        catch
        {
            return false;
        }
    }

    private static string ProcessLine(string line)
    {
        // Remove trailing whitespace (PGP clear signing requirement)
        return line.TrimEnd();
    }

    private async Task<(PgpSecretKey secretKey, PgpPrivateKey privateKey)> ReadSecretAndPrivateKeyAsync()
    {
        await using var keyIn = File.OpenRead(_privateKeyPath);
        using var decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var pgpSecretKeyRingBundle = new PgpSecretKeyRingBundle(decoderStream);

        foreach (PgpSecretKeyRing keyRing in pgpSecretKeyRingBundle.GetKeyRings())
        {
            foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys())
            {
                if (secretKey.IsSigningKey)
                {
                    var privateKey = secretKey.ExtractPrivateKey(_passphrase.ToCharArray());
                    return (secretKey, privateKey);
                }
            }
        }

        throw new InvalidOperationException("No signing key found in keyring");
    }

    private async Task<PgpPublicKey> ReadPublicKeyAsync()
    {
        await using var keyIn = File.OpenRead(_publicKeyPath);
        using var decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var pgpPublicKeyRingBundle = new PgpPublicKeyRingBundle(decoderStream);

        foreach (PgpPublicKeyRing keyRing in pgpPublicKeyRingBundle.GetKeyRings())
        {
            foreach (PgpPublicKey publicKey in keyRing.GetPublicKeys())
            {
                if (!publicKey.IsEncryptionKey)
                {
                    return publicKey;
                }
            }
        }

        throw new InvalidOperationException("No verification key found in keyring");
    }

    private static PgpKeyRingGenerator GenerateKeyRingGenerator(string identity, char[] passphrase)
    {
        var keyGenerationParameters = new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048);

        var rsaKeyPairGenerator = new RsaKeyPairGenerator();
        rsaKeyPairGenerator.Init(keyGenerationParameters);

        var masterKeyPair = new PgpKeyPair(
            PublicKeyAlgorithmTag.RsaSign,
            rsaKeyPairGenerator.GenerateKeyPair(),
            DateTime.UtcNow);

        var signatureSubpacketGenerator = new PgpSignatureSubpacketGenerator();
        signatureSubpacketGenerator.SetKeyFlags(false,
            PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
        signatureSubpacketGenerator.SetPreferredHashAlgorithms(false,
            new[] { (int)HashAlgorithmTag.Sha256, (int)HashAlgorithmTag.Sha512 });

        return new PgpKeyRingGenerator(
            PgpSignature.PositiveCertification,
            masterKeyPair,
            identity,
            SymmetricKeyAlgorithmTag.Aes256,
            HashAlgorithmTag.Sha256,
            passphrase,
            true,
            signatureSubpacketGenerator.Generate(),
            null,
            new SecureRandom());
    }
}
