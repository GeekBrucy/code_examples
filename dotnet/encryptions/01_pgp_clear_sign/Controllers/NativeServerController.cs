using _01_pgp_clear_sign.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace _01_pgp_clear_sign.Controllers;

/// <summary>
/// Server using native .NET cryptography (no third-party libs)
/// </summary>
[ApiController]
[Route("api/native/server")]
public class NativeServerController : ControllerBase
{
    private readonly INativeClearSignService _signService;
    private readonly string _outputDirectory;

    public NativeServerController(INativeClearSignService signService, IConfiguration configuration)
    {
        _signService = signService;
        _outputDirectory = configuration["Native:OutputDirectory"] ?? "temp";
    }

    /// <summary>
    /// Signs a JSON document using native .NET RSA and saves it to disk
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

        var fileName = $"native_signed_{DateTime.UtcNow:yyyyMMdd_HHmmss}.txt";
        var filePath = Path.Combine(_outputDirectory, fileName);
        await System.IO.File.WriteAllTextAsync(filePath, signedContent);

        return Ok(new
        {
            fileName,
            filePath = Path.GetFullPath(filePath)
        });
    }
}
