using generate_json_schema.Models.Base;

namespace generate_json_schema.Models
{
    public class Zoo
    {
        public required string Name { get; set; }
        public required string Location { get; set; }
        public int FoundedYear { get; set; }
        public List<Animal> Animals { get; set; } = [];
        public Dictionary<string, int> EnclosureCapacity { get; set; } = [];
    }
}