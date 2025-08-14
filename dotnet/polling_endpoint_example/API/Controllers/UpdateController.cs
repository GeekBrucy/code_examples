using Microsoft.AspNetCore.Mvc;
using API.Services;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UpdateController : ControllerBase
{
    private readonly IPollingService _pollingService;
    private readonly ILogger<UpdateController> _logger;

    public UpdateController(IPollingService pollingService, ILogger<UpdateController> logger)
    {
        _pollingService = pollingService;
        _logger = logger;
    }

    [HttpPut("{recordId}")]
    public async Task<IActionResult> UpdateRecord(
        string recordId,
        [FromBody] UpdateRecordRequest request)
    {
        if (string.IsNullOrEmpty(recordId))
        {
            return BadRequest("RecordId is required");
        }

        try
        {
            await _pollingService.UpdateExistingRecordAsync(recordId, request.Content, request.Priority);
            
            _logger.LogInformation("Updated record {RecordId}", recordId);
            
            return Ok(new { message = "Record updated successfully", recordId });
        }
        catch (ArgumentException ex)
        {
            return NotFound(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating record {RecordId}", recordId);
            return StatusCode(500, "Internal server error");
        }
    }
}

public class UpdateRecordRequest
{
    public object Content { get; set; } = new();
    public int? Priority { get; set; }
}