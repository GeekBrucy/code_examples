using NJsonSchema.Converters;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace generate_json_schema.Models.Base
{
    // STJ attributes — runtime serialization + StjSchemaService
    // Note: STJ does not allow the same derived type twice, so "canine" is NJsonSchema-only.
    // [JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
    // [JsonDerivedType(typeof(Dog), typeDiscriminator: "dog")]
    // [JsonDerivedType(typeof(Cat), typeDiscriminator: "cat")]
    // [JsonDerivedType(typeof(Dog))]
    // [JsonDerivedType(typeof(Cat))]

    // NJsonSchema attributes — schema generation only, no runtime effect on STJ
    // "canine" demonstrates multiple discriminators pointing to the same concrete class.
    // [JsonInheritance("dog", typeof(Dog))]
    // [JsonInheritance("canine", typeof(Dog))]
    // [JsonInheritance("cat", typeof(Cat))]
    // [JsonConverter(typeof(JsonInheritanceConverter), "discriminator")]

    // Subclass needed because [JsonConverter] does not forward constructor arguments.
    internal sealed class AnimalInheritanceConverter() : JsonInheritanceConverter<Animal>("Type");

    [JsonConverter(typeof(AnimalInheritanceConverter))]
    [KnownType(typeof(Dog))]
    [KnownType(typeof(Cat))]
    public abstract class Animal
    {
        public abstract string Type { get; }
        public required string Name { get; set; }
        public int AgeYears { get; set; }
        public bool IsEndangered { get; set; }
        public string? Diet { get; set; }
    }
}
