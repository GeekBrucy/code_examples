using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace API.Models;

public class UpdateEvent
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long EventSequence { get; set; } // The cursor - always incrementing
    
    public string UpdateRecordId { get; set; } = string.Empty; // References UpdateRecord.Id
    public string EventType { get; set; } = string.Empty; // "CREATE", "UPDATE", "DELETE"
    public DateTime EventTimestamp { get; set; } = DateTime.UtcNow;
    
    // Navigation property to the actual update record
    public UpdateRecord? UpdateRecord { get; set; }
}