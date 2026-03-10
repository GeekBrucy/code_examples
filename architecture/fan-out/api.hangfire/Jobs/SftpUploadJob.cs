using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// Stage 2b (fan-out): Uploads the zipped file to one SFTP destination.
/// Multiple instances of this job run in parallel — one per destination.
///
/// Completion tracking (fan-in without Hangfire Pro):
///   After a successful upload, this job atomically adds itself to a "completed"
///   set in Hangfire's storage and compares completedCount to expectedCount.
///   The LAST upload job to finish enqueues Stage3CleanupJob.
///
///   The distributed lock around the counter ensures that two jobs finishing
///   simultaneously don't both think they're last and enqueue cleanup twice.
/// </summary>
public class SftpUploadJob
{
    private readonly IBackgroundJobClient _jobClient;
    private readonly JobStorage _jobStorage;

    public SftpUploadJob(IBackgroundJobClient jobClient, JobStorage jobStorage)
    {
        _jobClient = jobClient;
        _jobStorage = jobStorage;
    }

    public async Task UploadAsync(int entityId, string zipPath, string destination)
    {
        // Per-(entity, destination) lock: prevents duplicate uploads if this job is retried
        var uploadLockKey = $"upload-lock:{entityId}:{destination}";
        using var connection = _jobStorage.GetConnection();
        using var uploadLock = connection.AcquireDistributedLock(uploadLockKey, timeout: TimeSpan.Zero);

        Console.WriteLine($"[SftpUpload] [{entityId}] Connecting to {destination}...");
        await Task.Delay(300);

        Console.WriteLine($"[SftpUpload] [{entityId}] Uploading {zipPath} to {destination}...");
        await Task.Delay(500);

        Console.WriteLine($"[SftpUpload] [{entityId}] Upload to {destination} complete.");

        // --- Fan-in: track completion and trigger Stage 3 if this is the last upload ---

        // Counter lock: ensures only one upload job at a time reads + writes the counter,
        // preventing two concurrent jobs both thinking they're the last one.
        var counterLockKey = $"upload-counter-lock:{entityId}";
        using var counterLock = connection.AcquireDistributedLock(counterLockKey, TimeSpan.FromSeconds(10));

        // Mark this destination as done
        using var writeTx = connection.CreateWriteTransaction();
        writeTx.AddToSet(Stage2PrepareJob.CompletedUploadsKey(entityId), destination);
        writeTx.Commit();

        var completed = connection.GetAllItemsFromSet(Stage2PrepareJob.CompletedUploadsKey(entityId));
        var expectedSet = connection.GetAllItemsFromSet(Stage2PrepareJob.ExpectedUploadsKey(entityId));
        var expectedCount = expectedSet.Count > 0 && int.TryParse(expectedSet.First(), out var n) ? n : 0;

        Console.WriteLine($"[SftpUpload] [{entityId}] Progress: {completed.Count}/{expectedCount} uploads done.");

        if (completed.Count >= expectedCount)
        {
            Console.WriteLine($"[SftpUpload] [{entityId}] All uploads finished. Enqueuing cleanup...");

            // Clean up the tracking sets so they don't accumulate in storage
            using var cleanTx = connection.CreateWriteTransaction();
            foreach (var d in completed)
                cleanTx.RemoveFromSet(Stage2PrepareJob.CompletedUploadsKey(entityId), d);
            foreach (var e in expectedSet)
                cleanTx.RemoveFromSet(Stage2PrepareJob.ExpectedUploadsKey(entityId), e);
            cleanTx.Commit();

            _jobClient.Enqueue<Stage3CleanupJob>(job => job.CleanupAsync(entityId, zipPath));
        }
    }
}
