using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// All pipeline stages run sequentially inside this single Hangfire job.
/// Data flows naturally through local variables — no job parameters to pass,
/// no ContinueJobWith, no counter-based fan-in needed.
///
/// The fan-out (SFTP uploads) is handled with Task.WhenAll inside this job,
/// giving parallel execution without spawning separate Hangfire jobs.
///
/// Trade-off vs. chained separate jobs:
///   PRO  — much simpler; no coordination plumbing required
///   CON  — if Stage 3 (cleanup) fails, Hangfire retries the whole job,
///          including Stage 1 (transform) again. Acceptable when stages are
///          cheap to re-run; use separate chained jobs when Stage 1 is expensive.
/// </summary>
public class WorkflowJob
{
    private readonly JobStorage _jobStorage;

    // SFTP destinations — in a real system these would come from config/DB
    private static readonly string[] SftpDestinations = ["sftp-server-au", "sftp-server-us", "sftp-server-eu"];

    public WorkflowJob(JobStorage jobStorage)
    {
        _jobStorage = jobStorage;
    }

    public async Task StartAsync(int entityId)
    {
        // Duplicate check: if a workflow for this entity is already in-flight,
        // AcquireDistributedLock throws → Hangfire retries this job later.
        var workflowLockKey = $"workflow-active:{entityId}";
        using var connection = _jobStorage.GetConnection();
        using var workflowLock = connection.AcquireDistributedLock(workflowLockKey, timeout: TimeSpan.Zero);

        // ── Stage 1: Transform ───────────────────────────────────────────────
        Console.WriteLine($"[Workflow] [{entityId}] Stage 1 — transforming data...");
        await Task.Delay(500); // simulate work
        var transformedData = $"transformed-payload-for-{entityId}"; // result lives in a local variable
        Console.WriteLine($"[Workflow] [{entityId}] Stage 1 complete.");

        // ── Stage 2a: Prepare (JSON → zip) ───────────────────────────────────
        Console.WriteLine($"[Workflow] [{entityId}] Stage 2 — serializing to JSON...");
        await Task.Delay(100);
        var zipPath = $"temp/entity_{entityId}.zip";
        Console.WriteLine($"[Workflow] [{entityId}] Zipping → {zipPath}");
        await Task.Delay(150);
        Console.WriteLine($"[Workflow] [{entityId}] Zip ready. Fanning out {SftpDestinations.Length} uploads...");

        // ── Stage 2b: Fan-out SFTP uploads (parallel, in-process) ────────────
        // Task.WhenAll runs all uploads concurrently inside this job.
        // Each upload gets the zip path directly — no serialization needed.
        await Task.WhenAll(SftpDestinations.Select(dest => UploadAsync(entityId, zipPath, dest, transformedData)));

        // ── Stage 3: Cleanup ─────────────────────────────────────────────────
        Console.WriteLine($"[Workflow] [{entityId}] Stage 3 — cleaning up {zipPath}...");
        // In real code: File.Delete(zipPath); File.Delete(jsonPath);
        await Task.Delay(50);
        Console.WriteLine($"[Workflow] [{entityId}] Pipeline complete.");
    }

    private static async Task UploadAsync(int entityId, string zipPath, string destination, string payload)
    {
        Console.WriteLine($"[SftpUpload] [{entityId}] Connecting to {destination}...");
        await Task.Delay(300);
        Console.WriteLine($"[SftpUpload] [{entityId}] Uploading {zipPath} to {destination} (payload: {payload[..20]}...)");
        await Task.Delay(500);
        Console.WriteLine($"[SftpUpload] [{entityId}] Upload to {destination} complete.");
    }
}
