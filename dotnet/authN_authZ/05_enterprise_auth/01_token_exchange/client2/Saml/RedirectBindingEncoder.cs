using System.IO.Compression;
using System.Text;

namespace client2.Saml;

public static class RedirectBindingEncoder
{
    public static string EncodeAuthnRequestForRedirect(string xml)
    {
        var bytes = Encoding.UTF8.GetBytes(xml);

        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(bytes, 0, bytes.Length);
        }

        var compressed = output.ToArray();
        var base64 = Convert.ToBase64String(compressed);

        return Uri.EscapeDataString(base64);
    }
}
