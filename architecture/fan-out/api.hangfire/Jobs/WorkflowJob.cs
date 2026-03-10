using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// Orchestrates the full pipeline for one entity:
///   1. Duplicate check — if a workflow for this entity is already running, fail fast and retry later
///   2. Compute shared file paths upfront (required so ContinueJobWith can pass them to each stage)
///   3. Chain Stage 1 → Stage 2 using ContinueJobWith (free Hangfire feature)
///   4. Stage 3 (cleanup) is triggered internally by the last SftpUploadJob
///
/// ContinueJobWith vs Hangfire Pro BatchJob:
///   ContinueJobWith  — free, chains ONE job to ONE successor
///   BatchJob         — Pro only, fan-out with native fan-in continuation after ALL parallel jobs finish
///
/// We use ContinueJobWith for the linear Stage 1 → Stage 2 chain.
/// The fan-in before Stage 3 is handled with a completion counter in Hangfire's set storage.
/// </summary>
public class WorkflowJob
{
    private readonly IBackgroundJobClient _jobClient;
    private readonly JobStorage _jobStorage;

    // SFTP destinations — in a real system these would come from config/DB
    private static readonly string[] SftpDestinations = ["sftp-server-au", "sftp-server-us", "sftp-server-eu"];

    public WorkflowJob(IBackgroundJobClient jobClient, JobStorage jobStorage)
    {
        _jobClient = jobClient;
        _jobStorage = jobStorage;
    }

    public Task StartAsync(int entityId)
    {
        // Duplicate check: if a workflow for this entity is already in-flight,
        // AcquireDistributedLock throws → Hangfire retries this job later.
        var workflowLockKey = $"workflow-active:{entityId}";
        using var connection = _jobStorage.GetConnection();
        using var workflowLock = connection.AcquireDistributedLock(workflowLockKey, timeout: TimeSpan.Zero);

        // File paths are computed here so they can be passed to all stages upfront.
        // ContinueJobWith sets up the chain before any job runs, so paths must be known now.
        var jsonPath = $"temp/entity_{entityId}.json";
        var zipPath  = $"temp/entity_{entityId}.zip";

        // Chain Stage 1 → Stage 2 (linear, free Hangfire)
        var stage1Id = _jobClient.Enqueue<Stage1TransformJob>(
            job => job.TransformAsync(entityId, jsonPath));

        _jobClient.ContinueJobWith<Stage2PrepareJob>(
            stage1Id,
            job => job.PrepareAndFanOutAsync(entityId, jsonPath, zipPath, SftpDestinations));

        // Stage 3 is NOT chained here — it is enqueued by the last SftpUploadJob.
        // See SftpUploadJob for the completion counter logic.

        Console.WriteLine($"[Workflow] [{entityId}] Pipeline scheduled: " +
                          $"Stage1 → Stage2 → ({SftpDestinations.Length}× SftpUpload) → Stage3Cleanup");

        return Task.CompletedTask;
    }
}
