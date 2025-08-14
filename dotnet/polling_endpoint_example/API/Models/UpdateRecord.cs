using System.ComponentModel.DataAnnotations;

namespace API.Models;

public class UpdateRecord
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    public string Type { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow; // Track when record was last modified
    public string Source { get; set; } = string.Empty;
    public int Priority { get; set; } = 0;
}