using System.Threading.Channels;

namespace api.Services;

/// <summary>
/// Demonstrates fan-out using System.Threading.Channels.
///
/// Pattern:
///   - 1 producer enqueues work items into a bounded channel
///   - N consumers drain the channel concurrently (fan-out)
///
/// Advantages over Task.WhenAll fan-out:
///   - Bounded capacity provides backpressure (producer blocks when channel is full)
///   - Consumers run as a fixed pool — no unbounded task explosion
///   - Works well for streaming/continuous workloads
/// </summary>
public class ChannelFanOutService : BackgroundService
{
    private readonly Channel<WorkItem> _channel;
    private readonly ILogger<ChannelFanOutService> _logger;

    // Number of concurrent consumers
    public const int ConsumerCount = 3;

    public ChannelFanOutService(ILogger<ChannelFanOutService> logger)
    {
        _logger = logger;

        // Bounded channel: producer will block (or fail) if > 100 items are queued
        _channel = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(capacity: 100)
        {
            FullMode = BoundedChannelFullMode.Wait,      // producer waits when full
            SingleWriter = false,                         // multiple producers allowed
            SingleReader = false                          // multiple consumers allowed
        });
    }

    /// <summary>Enqueue a work item from outside (e.g., from a controller).</summary>
    public async ValueTask EnqueueAsync(WorkItem item, CancellationToken cancellationToken = default)
    {
        await _channel.Writer.WriteAsync(item, cancellationToken);
        _logger.LogInformation("Enqueued work item {Id}", item.Id);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ChannelFanOutService starting {Count} consumers", ConsumerCount);

        // Fan-out: spin up N consumer tasks that all read from the same channel
        var consumers = Enumerable
            .Range(1, ConsumerCount)
            .Select(consumerId => ConsumeAsync(consumerId, stoppingToken))
            .ToArray();

        await Task.WhenAll(consumers);

        _logger.LogInformation("ChannelFanOutService stopped");
    }

    private async Task ConsumeAsync(int consumerId, CancellationToken stoppingToken)
    {
        _logger.LogInformation("Consumer {Id} started", consumerId);

        // ReadAllAsync drains the channel until it's completed and empty
        await foreach (var item in _channel.Reader.ReadAllAsync(stoppingToken))
        {
            _logger.LogInformation("Consumer {ConsumerId} processing item {ItemId}", consumerId, item.Id);

            await ProcessItemAsync(item, stoppingToken);

            _logger.LogInformation("Consumer {ConsumerId} finished item {ItemId}", consumerId, item.Id);
        }

        _logger.LogInformation("Consumer {Id} stopped", consumerId);
    }

    private static async Task ProcessItemAsync(WorkItem item, CancellationToken cancellationToken)
    {
        // Simulate processing work
        await Task.Delay(item.ProcessingDelayMs, cancellationToken);
    }
}

public record WorkItem(Guid Id, string Payload, int ProcessingDelayMs);
