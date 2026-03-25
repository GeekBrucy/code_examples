namespace generate_json_schema.Models
{
    public class Habitat
    {
        public required string Zone { get; set; }
        public double SquareMeters { get; set; }
        public bool IsOutdoor { get; set; }
    }
}
