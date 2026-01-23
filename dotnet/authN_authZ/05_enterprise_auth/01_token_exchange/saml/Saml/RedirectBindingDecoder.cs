using System.IO.Compression;
using System.Text;

namespace saml.Saml
{
    public static class RedirectBindingDecoder
    {
        public static string DecodeSamlRequestFromRedirect(string samlRequest)
        {
            // In ASP.NET, querystring is already URL-decoded, but be tolerant:
            samlRequest = Uri.UnescapeDataString(samlRequest);

            var compressed = Convert.FromBase64String(samlRequest);

            // SAML HTTP-Redirect uses DEFLATE (RFC1951). Different libs/platforms
            // sometimes wrap it with zlib header (RFC1950). We'll try both.
            if (TryInflateRawDeflate(compressed, out var xml))
                return xml;

            if (TryInflateZlib(compressed, out xml))
                return xml;

            if (compressed.Length > 2 && TryInflateRawDeflate(compressed.AsSpan(2).ToArray(), out xml))
                return xml;
            throw new InvalidOperationException("Failed to inflate SAML Request (unsupported DEFLATE format).");
        }

        private static bool TryInflateRawDeflate(byte[] data, out string xml)
        {
            try
            {
                using var input = new MemoryStream(data);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                xml = Encoding.UTF8.GetString(output.ToArray());
                return true;
            }
            catch (System.Exception)
            {
                xml = "";
                return false;
            }
        }

        private static bool TryInflateZlib(byte[] data, out string xml)
        {
            try
            {
                using var input = new MemoryStream(data);
                using var zlib = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                zlib.CopyTo(output);
                xml = Encoding.UTF8.GetString(output.ToArray());
                return true;
            }
            catch (System.Exception)
            {
                xml = "";
                return false;
            }
        }
    }
}