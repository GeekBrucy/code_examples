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

        // Store expected upload count BEFORE enqueuing any upload job.
        // SftpUploadJob reads this to know when all uploads are done.
        using var connection = _jobStorage.GetConnection();
        using var tx = connection.CreateWriteTransaction();
        tx.AddToSet(ExpectedUploadsKey(entityId), destinations.Length.ToString());
        tx.Commit();

        // Fan-out: one independent Hangfire job per destination
        Console.WriteLine($"[Stage2] [{entityId}] Fanning out {destinations.Length} upload jobs...");

        foreach (var destination in destinations)
        {
            _jobClient.Enqueue<SftpUploadJob>(
                job => job.UploadAsync(entityId, zipPath, destination));

            Console.WriteLine($"[Stage2] [{entityId}] Enqueued upload → {destination}");
        }

        Console.WriteLine($"[Stage2] [{entityId}] All upload jobs enqueued. Stage 3 will run after the last upload.");
    }
}
