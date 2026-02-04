using _01_pgp_clear_sign.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace _01_pgp_clear_sign.Controllers;

/// <summary>
/// Server using X.509 certificate signing (.pfx)
/// </summary>
[ApiController]
[Route("api/cert/server")]
public class CertServerController : ControllerBase
{
    private readonly ICertificateClearSignService _signService;
    private readonly string _outputDirectory;

    public CertServerController(ICertificateClearSignService signService, IConfiguration configuration)
    {
        _signService = signService;
        _outputDirectory = configuration["Certificate:OutputDirectory"] ?? "temp";
    }

    /// <summary>
    /// Signs a JSON document using X.509 certificate and saves it to disk
    /// </summary>
    [HttpPost("sign")]
    public async Task<IActionResult> SignDocument([FromBody] object document)
    {
        Directory.CreateDirectory(_outputDirectory);

        var json = JsonSerializer.Serialize(document, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        var signedContent = await _signService.ClearSignAsync(json);

        var fileName = $"cert_signed_{DateTime.UtcNow:yyyyMMdd_HHmmss}.txt";
        var filePath = Path.Combine(_outputDirectory, fileName);
        await System.IO.File.WriteAllTextAsync(filePath, signedContent);

        return Ok(new
        {
            fileName,
            filePath = Path.GetFullPath(filePath)
        });
    }
}
