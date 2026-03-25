using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// Stage 3: Cleans up temp files and all Hangfire tracking sets for this entity.
/// Enqueued by the last SftpUploadJob to finish (via the completion counter).
/// Safe to retry on any server — file deletes and set removals are both idempotent.
/// </summary>
public class Stage3CleanupJob
{
    private readonly JobStorage _jobStorage;

    public Stage3CleanupJob(JobStorage jobStorage)
    {
        _jobStorage = jobStorage;
    }

    public async Task CleanupAsync(int entityId, string zipPath)
    {
        Console.WriteLine($"[Stage3] [{entityId}] Cleaning up temp files...");

        // In real code:
        // var jsonPath = $"temp/entity_{entityId}.json";
        // if (File.Exists(jsonPath)) File.Delete(jsonPath);
        // if (File.Exists(zipPath)) File.Delete(zipPath);

        await Task.Delay(50);

        // Remove the enqueued-uploads tracking set (used by Stage 2 retry logic)
        using var connection = _jobStorage.GetConnection();
        var enqueued = connection.GetAllItemsFromSet(Stage2PrepareJob.EnqueuedUploadsKey(entityId));
        if (enqueued.Count > 0)
        {
            using var tx = connection.CreateWriteTransaction();
            foreach (var d in enqueued)
                tx.RemoveFromSet(Stage2PrepareJob.EnqueuedUploadsKey(entityId), d);
            tx.Commit();
        }

        Console.WriteLine($"[Stage3] [{entityId}] Deleted {zipPath} and tracking sets. Pipeline complete.");
    }
}
