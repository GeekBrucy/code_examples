using System.Text.Json;
using Json.Schema;
using Json.Schema.Generation;

namespace generate_json_schema.Services;

// Uses JsonSchema.Net.Generation — compatible with .NET 8+, built on System.Text.Json.
// This library reads [JsonDerivedType] and [JsonPolymorphic] natively, so no custom
// post-processing is needed for polymorphic types.
public sealed class JsonSchemaNetService : IJsonSchemaService
{
    private static readonly SchemaGeneratorConfiguration Config = new();

    public string GenerateSchema(Type type)
    {
        var schema = new JsonSchemaBuilder().FromType(type, Config).Build();
        return JsonSerializer.Serialize(schema, new JsonSerializerOptions { WriteIndented = true });
    }
}
