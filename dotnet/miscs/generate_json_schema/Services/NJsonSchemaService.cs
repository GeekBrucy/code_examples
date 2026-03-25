using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using generate_json_schema.Models;
using NJsonSchema;
using NJsonSchema.Generation;


namespace generate_json_schema.Services;

// Compatible with .NET 8+.
//
// Polymorphism strategy:
//   NJsonSchema naturally emits $ref: Animal wherever Animal is used (e.g. array items).
//   After generation we walk the JSON tree and replace every such $ref with an inline
//   oneOf: [$ref Dog, $ref Cat] + discriminator at the usage site.
//   Animal's definition stays clean — just shared base properties.
//   Dog/Cat definitions keep their allOf: [$ref Animal] + own properties.
//
//   allOf arrays are intentionally skipped during traversal so the inheritance
//   refs inside Dog/Cat definitions are left untouched.
//
// Multiple discriminators → same concrete class:
//   oneOf is deduplicated by type so Dog appears once, but discriminator.mapping
//   lists all discriminator values (including duplicates) pointing to the same $ref.
//
// Default discriminator:
//   Pass defaultDiscriminatorValue to mark one concrete type as the assumed default
//   when $type is absent. The JSON Schema "default" keyword is added to the $type
//   property in each polymorphic base type's definition. This is a documentation/
//   tooling hint — validators do not enforce defaults.
public sealed class NJsonSchemaService : IJsonSchemaService
{
    private readonly string? _defaultDiscriminatorValue;

    /// <param name="defaultDiscriminatorValue">
    /// Optional. When set, adds <c>"default": value</c> to the <c>$type</c>
    /// discriminator property in every polymorphic base type's definition.
    /// </param>
    public NJsonSchemaService(string? defaultDiscriminatorValue = null)
    {
        _defaultDiscriminatorValue = defaultDiscriminatorValue;
    }

    public string GenerateSchema(Type type)
    {
        var settings = new SystemTextJsonSchemaGeneratorSettings
        {
            SchemaType = SchemaType.JsonSchema,
            FlattenInheritanceHierarchy = true,
            // GenerateAbstractProperties = true,

        };

        var test = JsonSchema.FromType<Zoo>();

        return test.ToJson();
        var polymorphicTypes = CollectPolymorphicTypes(type);

        var generator = new JsonSchemaGenerator(settings);
        JsonSchema schema = generator.Generate(type);

        var node = JsonNode.Parse(schema.ToJson())!;

        // Replace $ref pointers to polymorphic base types with oneOf at usage sites.
        // allOf traversal is skipped to preserve inheritance refs.
        ReplacePolymorphicRefs(node, polymorphicTypes);

        // Optionally annotate each polymorphic base's $type property with "default".
        if (_defaultDiscriminatorValue is not null)
            AddDefaultDiscriminator(node, polymorphicTypes, _defaultDiscriminatorValue);

        return JsonSerializer.Serialize(node, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Walks the JSON tree. When a child node is a bare <c>{ "$ref": "#/definitions/X" }</c>
    /// where X is a known polymorphic base, replaces it with a oneOf + discriminator node.
    /// Skips the <c>allOf</c> key so inheritance refs inside definitions are preserved.
    /// </summary>
    private static void ReplacePolymorphicRefs(
        JsonNode node,
        Dictionary<string, (Type BaseType, List<JsonDerivedTypeAttribute> DerivedAttrs)> polymorphicTypes)
    {
        if (node is JsonObject obj)
        {
            var keys = obj.Select(kv => kv.Key).ToList();
            foreach (var key in keys)
            {
                // Skip allOf so Dog/Cat inheritance refs are not replaced
                if (key == "allOf") continue;

                var child = obj[key];
                if (child is null) continue;

                if (child is JsonObject childObj &&
                    TryGetPolymorphicDefName(childObj, polymorphicTypes, out var defName))
                {
                    obj[key] = BuildOneOfNode(polymorphicTypes[defName!]);
                }
                else
                {
                    ReplacePolymorphicRefs(child, polymorphicTypes);
                }
            }
        }
        else if (node is JsonArray arr)
        {
            for (var i = 0; i < arr.Count; i++)
            {
                var item = arr[i];
                if (item is null) continue;

                if (item is JsonObject itemObj &&
                    TryGetPolymorphicDefName(itemObj, polymorphicTypes, out var defName))
                {
                    arr[i] = BuildOneOfNode(polymorphicTypes[defName!]);
                }
                else
                {
                    ReplacePolymorphicRefs(item, polymorphicTypes);
                }
            }
        }
    }

    private static bool TryGetPolymorphicDefName(
        JsonObject obj,
        Dictionary<string, (Type, List<JsonDerivedTypeAttribute>)> polymorphicTypes,
        out string? defName)
    {
        defName = null;
        if (!obj.TryGetPropertyValue("$ref", out var refNode)) return false;
        var refValue = refNode?.GetValue<string>();
        if (refValue is null || !refValue.StartsWith("#/definitions/")) return false;

        var name = refValue["#/definitions/".Length..];
        if (!polymorphicTypes.ContainsKey(name)) return false;

        defName = name;
        return true;
    }

    private static JsonObject BuildOneOfNode(
        (Type BaseType, List<JsonDerivedTypeAttribute> DerivedAttrs) polyInfo)
    {
        var (baseType, derivedAttrs) = polyInfo;
        var polymorphicAttr = baseType.GetCustomAttribute<JsonPolymorphicAttribute>()!;
        var discriminatorName = polymorphicAttr.TypeDiscriminatorPropertyName ?? "$type";

        var oneOfArray = new JsonArray();
        var mappingNode = new JsonObject();

        // oneOf entries — one per unique derived type (deduped)
        var seen = new HashSet<Type>();
        foreach (var attr in derivedAttrs)
        {
            var key = attr.TypeDiscriminator?.ToString();
            var refPath = $"#/definitions/{attr.DerivedType.Name}";

            // Discriminator mapping includes all keys, even duplicates pointing to the same type
            if (key is not null)
                mappingNode[key] = JsonValue.Create(refPath);

            if (seen.Add(attr.DerivedType))
                oneOfArray.Add(new JsonObject { ["$ref"] = JsonValue.Create(refPath) });
        }

        return new JsonObject
        {
            ["oneOf"] = oneOfArray,
            ["discriminator"] = new JsonObject
            {
                ["propertyName"] = JsonValue.Create(discriminatorName),
                ["mapping"] = mappingNode,
            },
        };
    }

    /// <summary>
    /// Walks the CLR type graph and collects every type that has
    /// <see cref="JsonDerivedTypeAttribute"/>, keyed by simple class name.
    /// </summary>
    private static Dictionary<string, (Type BaseType, List<JsonDerivedTypeAttribute> DerivedAttrs)>
        CollectPolymorphicTypes(Type rootType)
    {
        var result = new Dictionary<string, (Type, List<JsonDerivedTypeAttribute>)>();
        var visited = new HashSet<Type>();
        var queue = new Queue<Type>();
        queue.Enqueue(rootType);

        while (queue.Count > 0)
        {
            var t = queue.Dequeue();
            if (!visited.Add(t) || t == typeof(string) || t.IsPrimitive || t.IsEnum) continue;

            var derivedAttrs = t.GetCustomAttributes<JsonDerivedTypeAttribute>().ToList();
            if (derivedAttrs.Count > 0)
            {
                result[t.Name] = (t, derivedAttrs);
                foreach (var a in derivedAttrs)
                    queue.Enqueue(a.DerivedType);
            }

            foreach (var prop in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                var propType = prop.PropertyType;
                if (propType.IsGenericType)
                    foreach (var arg in propType.GetGenericArguments())
                        queue.Enqueue(arg);
                else
                    queue.Enqueue(propType);
            }
        }

        return result;
    }

    /// <summary>
    /// For each polymorphic base type in <c>definitions</c>, adds <c>"default": value</c>
    /// to the <c>$type</c> discriminator property so tooling knows which concrete type to
    /// assume when the discriminator is absent.
    /// </summary>
    private static void AddDefaultDiscriminator(
        JsonNode root,
        Dictionary<string, (Type BaseType, List<JsonDerivedTypeAttribute> DerivedAttrs)> polymorphicTypes,
        string defaultValue)
    {
        if (root["definitions"] is not JsonObject definitions) return;

        foreach (var (defName, (baseType, _)) in polymorphicTypes)
        {
            if (definitions[defName] is not JsonObject defNode) continue;

            var polymorphicAttr = baseType.GetCustomAttribute<JsonPolymorphicAttribute>();
            if (polymorphicAttr is null) continue;

            var discriminatorName = polymorphicAttr.TypeDiscriminatorPropertyName ?? "$type";

            // Locate the $type property inside "properties"
            if (defNode["properties"] is not JsonObject props) continue;
            if (props[discriminatorName] is not JsonObject discProp) continue;

            discProp["default"] = JsonValue.Create(defaultValue);
        }
    }
}
