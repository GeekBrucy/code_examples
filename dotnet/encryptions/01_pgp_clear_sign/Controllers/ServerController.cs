using System.Text.Json;
using _01_pgp_clear_sign.Services;
using Microsoft.AspNetCore.Mvc;

namespace _01_pgp_clear_sign.Controllers;

/// <summary>
/// Server - signs JSON documents and saves them to disk
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class ServerController : ControllerBase
{
    private readonly IPgpClearSignService _pgpService;
    private readonly string _outputDirectory;

    public ServerController(IPgpClearSignService pgpService, IConfiguration configuration)
    {
        _pgpService = pgpService;
        _outputDirectory = configuration["Pgp:OutputDirectory"] ?? "temp";
    }

    /// <summary>
    /// Signs a JSON document and saves it to disk
    /// </summary>
    [HttpPost("sign")]
    public async Task<IActionResult> SignDocument([FromBody] object document)
    {
        Directory.CreateDirectory(_outputDirectory);

        var json = JsonSerializer.Serialize(document, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        var signedContent = await _pgpService.ClearSignAsync(json);

        var fileName = $"signed_{DateTime.UtcNow:yyyyMMdd_HHmmss}.asc";
        var filePath = Path.Combine(_outputDirectory, fileName);
        await System.IO.File.WriteAllTextAsync(filePath, signedContent);

        return Ok(new
        {
            fileName,
            filePath = Path.GetFullPath(filePath)
        });
    }
}
