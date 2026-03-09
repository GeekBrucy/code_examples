using api.Services;
using Microsoft.AspNetCore.Mvc;

namespace api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ChannelController : ControllerBase
{
    private readonly ChannelFanOutService _channelFanOutService;

    public ChannelController(ChannelFanOutService channelFanOutService)
    {
        _channelFanOutService = channelFanOutService;
    }

    /// <summary>
    /// Enqueue work items into the channel. The background service fans them out
    /// across multiple concurrent consumers. Fire-and-forget from the caller's perspective.
    /// </summary>
    [HttpPost("enqueue")]
    public async Task<IActionResult> Enqueue([FromBody] EnqueueRequest request, CancellationToken cancellationToken)
    {
        if (request.Count <= 0 || request.Count > 50)
            return BadRequest("Count must be between 1 and 50.");

        var items = Enumerable.Range(1, request.Count)
            .Select(_ => new WorkItem(Guid.NewGuid(), request.Payload, request.ProcessingDelayMs))
            .ToList();

        foreach (var item in items)
            await _channelFanOutService.EnqueueAsync(item, cancellationToken);

        return Accepted(new
        {
            Enqueued = items.Count,
            Message = $"{items.Count} items enqueued. Watch the logs to see {ChannelFanOutService.ConsumerCount} consumers processing them in parallel."
        });
    }
}

public record EnqueueRequest(int Count, string Payload, int ProcessingDelayMs = 300);
