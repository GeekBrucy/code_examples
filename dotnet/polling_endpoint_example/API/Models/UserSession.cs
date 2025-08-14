using System.ComponentModel.DataAnnotations;

namespace API.Models;

public class UserSession
{
    [Key]
    public string UserId { get; set; } = string.Empty;
    public DateTime LastSync { get; set; }
    public long LastEventSequence { get; set; } = 0; // Last event sequence this user has seen
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}