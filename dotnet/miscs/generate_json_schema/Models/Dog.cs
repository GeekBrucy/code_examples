using generate_json_schema.Models.Base;
using NJsonSchema.Converters;

namespace generate_json_schema.Models
{
    [JsonInheritance("Type", typeof(Animal))]
    public class Dog : Animal
    {
        public override string Type => "Dog";
        public required string Breed { get; set; }
        public bool IsGuardDog { get; set; }
        public int TrainingLevel { get; set; }
        public Habitat? Habitat { get; set; }
    }
}