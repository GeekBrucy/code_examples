using generate_json_schema.Models.Base;
using NJsonSchema.Converters;

namespace generate_json_schema.Models
{
    [JsonInheritance("Type", typeof(Animal))]
    public class Cat : Animal
    {
        public override string Type => "Cat";
        public bool IsIndoor { get; set; }
        public string? FurColor { get; set; }
    }
}