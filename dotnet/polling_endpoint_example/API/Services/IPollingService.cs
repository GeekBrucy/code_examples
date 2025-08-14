using API.Models;

namespace API.Services;

public interface IPollingService
{
    Task<PollingResponse> GetUpdatesAsync(string userId, string? cursor = null, DateTime? lastSync = null);
    Task CreateSampleUpdateAsync(string source, string type, object content, int priority = 0);
    Task UpdateExistingRecordAsync(string recordId, object newContent, int? newPriority = null);
}