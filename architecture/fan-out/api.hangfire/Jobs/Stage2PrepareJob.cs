using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// Stage 2: Reads the JSON file produced by Stage 1, zips it, then fans out
/// one SftpUploadJob per destination. These upload jobs run in parallel.
///
/// How Stage 3 (cleanup) is triggered:
///   Each SftpUploadJob atomically increments a completion counter stored in
///   Hangfire's set storage. The last job to finish sees completedCount == expectedCount
///   and enqueues Stage3CleanupJob. This replaces Hangfire Pro's BatchContinuation.
///
/// The expected count is stored in the set before any upload job is enqueued,
/// ensuring the counter is readable by all upload jobs without coordination.
/// </summary>
public class Stage2PrepareJob
{
    private readonly IBackgroundJobClient _jobClient;
    private readonly JobStorage _jobStorage;

    // Hangfire set key where each upload job records its completion
    public static string CompletedUploadsKey(int entityId) => $"uploads-done:{entityId}";

    // Hangfire set key that holds the expected upload count (single-element set used as a value store)
    public static string ExpectedUploadsKey(int entityId) => $"uploads-expected:{entityId}";

    // Hangfire set key tracking which destinations have already had a job enqueued.
    // Used by Stage 2 retry logic to avoid enqueueing duplicates across servers.
    public static string EnqueuedUploadsKey(int entityId) => $"uploads-enqueued:{entityId}";

    public Stage2PrepareJob(IBackgroundJobClient jobClient, JobStorage jobStorage)
    {
        _jobClient = jobClient;
        _jobStorage = jobStorage;
    }

    public async Task PrepareAndFanOutAsync(int entityId, string jsonPath, string zipPath, string[] destinations)
    {
        Console.WriteLine($"[Stage2] [{entityId}] Reading {jsonPath}...");
        await Task.Delay(100);

        Console.WriteLine($"[Stage2] [{entityId}] Zipping → {zipPath}");
        await Task.Delay(150);

        using var connection = _jobStorage.GetConnection();

        // Fan-out lock: ensures that if Stage 2 retries (on this or any other server),
        // it doesn't enqueue duplicate upload jobs for destinations already enqueued.
        // Safe across multiple load-balanced servers because the lock lives in SQL Server.
        using var fanOutLock = connection.AcquireDistributedLock(
            $"stage2-fanout:{entityId}", TimeSpan.FromSeconds(30));

        // "enqueued-uploads:{entityId}" tracks which destinations already have a job queued.
        // On retry, we skip destinations already recorded here.
        var alreadyEnqueued = connection.GetAllItemsFromSet(EnqueuedUploadsKey(entityId));
        var pending = destinations.Where(d => !alreadyEnqueued.Contains(d)).ToArray();

        // Expected count is the full destination count regardless of retry — upload jobs
        // that already ran still count toward the completion total.
        using var tx = connection.CreateWriteTransaction();
        tx.AddToSet(ExpectedUploadsKey(entityId), destinations.Length.ToString());
        tx.Commit();

        Console.WriteLine($"[Stage2] [{entityId}] Fanning out {pending.Length} upload jobs " +
                          $"({alreadyEnqueued.Count} already enqueued from prior attempt)...");

        foreach (var destination in pending)
        {
            _jobClient.Enqueue<SftpUploadJob>(job => job.UploadAsync(entityId, zipPath, destination));

            // Record immediately so a crash mid-loop doesn't re-enqueue on retry
            using var recordTx = connection.CreateWriteTransaction();
            recordTx.AddToSet(EnqueuedUploadsKey(entityId), destination);
            recordTx.Commit();

            Console.WriteLine($"[Stage2] [{entityId}] Enqueued upload → {destination}");
        }

        Console.WriteLine($"[Stage2] [{entityId}] All upload jobs enqueued. Stage 3 will run after the last upload.");
    }
}
