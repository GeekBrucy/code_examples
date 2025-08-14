using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using API.Models;
using API.Data;

namespace API.Services;

public class PollingService : IPollingService
{
    private readonly ILogger<PollingService> _logger;
    private readonly IMemoryCache _cache;
    private readonly PollingDbContext _context;

    public PollingService(ILogger<PollingService> logger, IMemoryCache cache, PollingDbContext context)
    {
        _logger = logger;
        _cache = cache;
        _context = context;
    }

    public async Task<PollingResponse> GetUpdatesAsync(string userId, string? cursor = null, DateTime? lastSync = null)
    {
        var now = DateTime.UtcNow;
        
        // Determine starting event sequence position
        var startEventSequence = await GetStartingEventSequenceAsync(userId, cursor, lastSync);
        
        // Get updates from database using event sequence
        var updates = await GetUpdatesFromEventSequenceAsync(startEventSequence);
        
        // Determine next cursor from the last event returned
        var nextCursor = updates.Any() ? updates.Last().SequenceNumber.ToString() : startEventSequence.ToString();
        
        // Update user session with latest event sequence and sync time
        await UpdateUserSessionAsync(userId, now, updates.Any() ? updates.Last().SequenceNumber : startEventSequence);

        var response = new PollingResponse
        {
            HasUpdates = updates.Count > 0,
            LastModified = now,
            Data = updates,
            NextPollAfterSeconds = 300, // 5 minutes
            NextCursor = nextCursor
        };

        _logger.LogInformation("Retrieved {UpdateCount} updates for user {UserId} from event sequence {StartSequence}", 
            updates.Count, userId, startEventSequence);
        
        return response;
    }

    private async Task<long> GetStartingEventSequenceAsync(string userId, string? cursor, DateTime? lastSync)
    {
        // Priority: explicit cursor > lastSync timestamp > user session event sequence > 0
        if (!string.IsNullOrEmpty(cursor) && long.TryParse(cursor, out var cursorValue))
        {
            return cursorValue;
        }
        
        if (lastSync.HasValue && lastSync != DateTime.MinValue)
        {
            // Find the last event sequence at or before the given timestamp
            var lastEvent = await _context.UpdateEvents
                .Where(e => e.EventTimestamp <= lastSync.Value)
                .OrderByDescending(e => e.EventSequence)
                .FirstOrDefaultAsync();
            return lastEvent?.EventSequence ?? 0;
        }
        
        // Fall back to user session event sequence
        var userSession = await _context.UserSessions.FindAsync(userId);
        return userSession?.LastEventSequence ?? 0;
    }
    
    private async Task<List<UpdateItem>> GetUpdatesFromEventSequenceAsync(long eventSequence)
    {
        // Query for events with EventSequence > cursor, then join to get current update records
        var eventRecords = await _context.UpdateEvents
            .Where(e => e.EventSequence > eventSequence)
            .Include(e => e.UpdateRecord) // Include the actual update record
            .OrderBy(e => e.EventSequence) // Always ordered by event sequence
            .Take(100) // Limit to prevent huge responses
            .ToListAsync();

        // Convert to UpdateItem DTOs, using current state of UpdateRecord
        var updates = new List<UpdateItem>();
        foreach (var eventRecord in eventRecords)
        {
            if (eventRecord.UpdateRecord != null) // Skip if record was deleted
            {
                updates.Add(new UpdateItem
                {
                    Id = eventRecord.UpdateRecord.Id,
                    SequenceNumber = eventRecord.EventSequence, // Use event sequence as cursor
                    Type = eventRecord.UpdateRecord.Type,
                    Content = string.IsNullOrEmpty(eventRecord.UpdateRecord.Content) ? new { } : 
                        JsonSerializer.Deserialize<object>(eventRecord.UpdateRecord.Content) ?? new { },
                    Timestamp = eventRecord.UpdateRecord.Timestamp,
                    Source = eventRecord.UpdateRecord.Source,
                    Priority = eventRecord.UpdateRecord.Priority
                });
            }
        }
        
        return updates;
    }

    private async Task UpdateUserSessionAsync(string userId, DateTime lastSync, long lastEventSequence)
    {
        var userSession = await _context.UserSessions.FindAsync(userId);
        
        if (userSession == null)
        {
            userSession = new UserSession
            {
                UserId = userId,
                LastSync = lastSync,
                LastEventSequence = lastEventSequence,
                CreatedAt = lastSync,
                UpdatedAt = lastSync
            };
            _context.UserSessions.Add(userSession);
        }
        else
        {
            userSession.LastSync = lastSync;
            userSession.LastEventSequence = lastEventSequence;
            userSession.UpdatedAt = lastSync;
        }

        await _context.SaveChangesAsync();
    }

    public async Task CreateSampleUpdateAsync(string source, string type, object content, int priority = 0)
    {
        var updateRecord = new UpdateRecord
        {
            Id = Guid.NewGuid().ToString(),
            Type = type,
            Content = JsonSerializer.Serialize(content),
            Timestamp = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Source = source,
            Priority = priority
        };

        // Add the update record
        _context.UpdateRecords.Add(updateRecord);
        
        // Create corresponding event for the cursor
        var updateEvent = new UpdateEvent
        {
            UpdateRecordId = updateRecord.Id,
            EventType = "CREATE",
            EventTimestamp = DateTime.UtcNow
        };
        
        _context.UpdateEvents.Add(updateEvent);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Created shared update from source {Source} of type {Type} with priority {Priority} and event sequence {EventSequence}", 
            source, type, priority, updateEvent.EventSequence);
    }
    
    public async Task UpdateExistingRecordAsync(string recordId, object newContent, int? newPriority = null)
    {
        var updateRecord = await _context.UpdateRecords.FindAsync(recordId);
        if (updateRecord == null)
        {
            throw new ArgumentException($"UpdateRecord with ID {recordId} not found");
        }
        
        // Update the record
        updateRecord.Content = JsonSerializer.Serialize(newContent);
        updateRecord.UpdatedAt = DateTime.UtcNow;
        if (newPriority.HasValue)
        {
            updateRecord.Priority = newPriority.Value;
        }
        
        // Create corresponding event for the cursor
        var updateEvent = new UpdateEvent
        {
            UpdateRecordId = recordId,
            EventType = "UPDATE",
            EventTimestamp = DateTime.UtcNow
        };
        
        _context.UpdateEvents.Add(updateEvent);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Updated record {RecordId} and created event sequence {EventSequence}", 
            recordId, updateEvent.EventSequence);
    }
}