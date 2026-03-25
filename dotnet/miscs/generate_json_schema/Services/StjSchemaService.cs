using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;
using System.Text.Json.Serialization.Metadata;

namespace generate_json_schema.Services;

// Requires .NET 9+ (System.Text.Json.Schema is not available on .NET 8)
public sealed class StjSchemaService : IJsonSchemaService
{
    private readonly JsonSerializerOptions _options = new(JsonSerializerDefaults.Web)
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
    };

    public string GenerateSchema(Type type)
    {
        JsonNode schemaNode = _options.GetJsonSchemaAsNode(type);
        return JsonSerializer.Serialize(schemaNode, new JsonSerializerOptions { WriteIndented = true });
    }
}
