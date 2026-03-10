namespace api.hangfire.Jobs;

/// <summary>
/// Stage 3: Cleans up temp files after all SFTP uploads are complete.
/// Enqueued by the last SftpUploadJob to finish (via the completion counter).
/// </summary>
public class Stage3CleanupJob
{
    public async Task CleanupAsync(int entityId, string zipPath)
    {
        Console.WriteLine($"[Stage3] [{entityId}] Cleaning up temp files...");

        // In real code:
        // var jsonPath = $"temp/entity_{entityId}.json";
        // if (File.Exists(jsonPath)) File.Delete(jsonPath);
        // if (File.Exists(zipPath)) File.Delete(zipPath);

        await Task.Delay(50);

        Console.WriteLine($"[Stage3] [{entityId}] Deleted {zipPath} and associated JSON. Pipeline complete.");
    }
}
