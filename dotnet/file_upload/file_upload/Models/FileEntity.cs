using System.ComponentModel.DataAnnotations;

namespace file_upload.Models
{
    public class FileEntity
    {
        public int Id { get; set; }
        
        [Required]
        public string FileName { get; set; } = string.Empty;
        
        [Required]
        public string OriginalName { get; set; } = string.Empty;
        
        [Required]
        public string ContentType { get; set; } = string.Empty;
        
        [Required]
        public byte[] Content { get; set; } = Array.Empty<byte>();
        
        public long Size { get; set; }
        
        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
        
        public string? Title { get; set; }
        
        public string? Description { get; set; }
    }
}