using _01_pgp_clear_sign.Services;
using Microsoft.AspNetCore.Mvc;

namespace _01_pgp_clear_sign.Controllers;

/// <summary>
/// Client using X.509 certificate verification (.cer)
/// </summary>
[ApiController]
[Route("api/cert/client")]
public class CertClientController : ControllerBase
{
    private readonly ICertificateClearSignService _signService;
    private readonly string _outputDirectory;

    public CertClientController(ICertificateClearSignService signService, IConfiguration configuration)
    {
        _signService = signService;
        _outputDirectory = configuration["Certificate:OutputDirectory"] ?? "temp";
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

        var files = Directory.GetFiles(_outputDirectory, "*.txt")
            .Select(Path.GetFileName)
            .ToArray();

        return Ok(new { files });
    }

    /// <summary>
    /// Reads a signed document, verifies signature, and returns the content
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
        var isValid = await _signService.VerifySignatureAsync(signedContent);

        var jsonContent = ExtractContent(signedContent);

        return Ok(new
        {
            fileName,
            isValid,
            content = jsonContent,
            rawSignedContent = signedContent
        });
    }

    private static string? ExtractContent(string signedContent)
    {
        var lines = signedContent.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var contentLines = new List<string>();
        var inContent = false;
        var passedEmptyLine = false;

        foreach (var line in lines)
        {
            if (line == "-----END CERTIFICATE SIGNED MESSAGE-----")
            {
                break;
            }

            if (inContent && passedEmptyLine)
            {
                contentLines.Add(line);
            }

            if (inContent && string.IsNullOrEmpty(line) && !passedEmptyLine)
            {
                passedEmptyLine = true;
            }

            if (line == "-----BEGIN CERTIFICATE SIGNED MESSAGE-----")
            {
                inContent = true;
            }
        }

        // Remove trailing empty lines
        while (contentLines.Count > 0 && string.IsNullOrEmpty(contentLines[^1]))
        {
            contentLines.RemoveAt(contentLines.Count - 1);
        }

        return contentLines.Count > 0 ? string.Join("\n", contentLines) : null;
    }
}
