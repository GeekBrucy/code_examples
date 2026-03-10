namespace api.hangfire.Jobs;

/// <summary>
/// Stage 1: Transform the raw entity data and save the result as a JSON file.
/// The JSON file path is decided by WorkflowJob upfront so that Stage 2 can
/// receive it as a parameter via ContinueJobWith.
/// </summary>
public class Stage1TransformJob
{
    public async Task TransformAsync(int entityId, string jsonPath)
    {
        Console.WriteLine($"[Stage1] [{entityId}] Starting transformation...");

        await Task.Delay(500); // simulate work

        Console.WriteLine($"[Stage1] [{entityId}] Transformation complete. Saving to {jsonPath}");

        // In real code:
        // var result = await _dataService.TransformAsync(entityId);
        // Directory.CreateDirectory(Path.GetDirectoryName(jsonPath)!);
        // await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(result));

        Console.WriteLine($"[Stage1] [{entityId}] JSON saved. Handing off to Stage 2.");
    }
}
