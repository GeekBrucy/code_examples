using Microsoft.AspNetCore.Mvc;
using API.Models;
using API.Services;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PollingController : ControllerBase
{
    private readonly IPollingService _pollingService;
    private readonly ILogger<PollingController> _logger;

    public PollingController(IPollingService pollingService, ILogger<PollingController> logger)
    {
        _pollingService = pollingService;
        _logger = logger;
    }

    [HttpGet("updates")]
    public async Task<ActionResult<PollingResponse>> GetUpdates(
        [FromQuery] string userId,
        [FromQuery] string? cursor = null,
        [FromQuery] DateTime? lastSync = null)
    {
        if (string.IsNullOrEmpty(userId))
        {
            return BadRequest("UserId is required");
        }

        try
        {
            var response = await _pollingService.GetUpdatesAsync(userId, cursor, lastSync);
            
            _logger.LogInformation("Polling request for user {UserId}, cursor: {Cursor}, lastSync: {LastSync}, hasUpdates: {HasUpdates}", 
                userId, cursor, lastSync, response.HasUpdates);
            
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing polling request for user {UserId}", userId);
            return StatusCode(500, "Internal server error");
        }
    }
}