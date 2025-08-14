using Microsoft.AspNetCore.Mvc;
using API.Services;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TestDataController : ControllerBase
{
    private readonly IPollingService _pollingService;
    private readonly ILogger<TestDataController> _logger;

    public TestDataController(IPollingService pollingService, ILogger<TestDataController> logger)
    {
        _pollingService = pollingService;
        _logger = logger;
    }

    [HttpPost("create-sample-update")]
    public async Task<IActionResult> CreateSampleUpdate(
        [FromQuery] string source = "test",
        [FromQuery] string type = "notification",
        [FromQuery] int priority = 0)
    {
        var content = new 
        {
            message = $"Sample {type} from {source}",
            timestamp = DateTime.UtcNow,
            value = new Random().Next(1, 100),
            details = "This is a shared resource update that all users will see"
        };

        await _pollingService.CreateSampleUpdateAsync(source, type, content, priority);
        
        return Ok(new { message = "Shared update created", source, type, priority });
    }
}