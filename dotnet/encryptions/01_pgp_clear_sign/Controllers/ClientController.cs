using _01_pgp_clear_sign.Services;
using Microsoft.AspNetCore.Mvc;


/// <summary>
/// Client - reads and verifies signed documents from disk
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class ClientController : ControllerBase
{
    private readonly IPgpClearSignService _pgpService;
    private readonly string _outputDirectory;

    public ClientController(IPgpClearSignService pgpService, IConfiguration configuration)
    {
        _pgpService = pgpService;
        _outputDirectory = configuration["Pgp:OutputDirectory"] ?? "temp";
    }

    /// <summary>
    /// Lists all signed documents
    /// </summary>
    [HttpGet("documents")]
    public IActionResult ListDocuments()
    {
        if (!Directory.Exists(_outputDirectory))
        {
            return Ok(new { files = Array.Empty<string>() });
        }

        var files = Directory.GetFiles(_outputDirectory, "*.asc")
            .Select(Path.GetFileName)
            .ToArray();

        return Ok(new { files });
    }

    /// <summary>
    /// Reads a signed document, verifies signature, and returns the content with verification status
    /// </summary>
    [HttpGet("documents/{fileName}")]
    public async Task<IActionResult> GetDocument(string fileName)
    {
        var filePath = Path.Combine(_outputDirectory, fileName);

        if (!System.IO.File.Exists(filePath))
        {
            return NotFound(new { error = $"File not found: {fileName}" });
        }

        var signedContent = await System.IO.File.ReadAllTextAsync(filePath);
        var isValid = await _pgpService.VerifySignatureAsync(signedContent);

        // Extract the JSON content from between the PGP headers
        var jsonContent = ExtractJsonFromSignedContent(signedContent);

        return Ok(new
        {
            fileName,
            isValid,
            content = jsonContent,
            rawSignedContent = signedContent
        });
    }

    private static string? ExtractJsonFromSignedContent(string signedContent)
    {
        // Find content between "Hash: SHA256\n\n" and "\n-----BEGIN PGP SIGNATURE-----"
        var lines = signedContent.Split('\n');
        var contentLines = new List<string>();
        var inContent = false;

        foreach (var line in lines)
        {
            if (line.StartsWith("-----BEGIN PGP SIGNATURE-----"))
            {
                break;
            }

            if (inContent)
            {
                contentLines.Add(line.TrimEnd('\r'));
            }

            if (line.StartsWith("Hash:"))
            {
                inContent = true;
            }
        }

        // Remove leading/trailing empty lines
        while (contentLines.Count > 0 && string.IsNullOrWhiteSpace(contentLines[0]))
            contentLines.RemoveAt(0);
        while (contentLines.Count > 0 && string.IsNullOrWhiteSpace(contentLines[^1]))
            contentLines.RemoveAt(contentLines.Count - 1);

        return contentLines.Count > 0 ? string.Join("\n", contentLines) : null;
    }
}
