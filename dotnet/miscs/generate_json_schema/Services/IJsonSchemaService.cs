namespace generate_json_schema.Services;

public interface IJsonSchemaService
{
    string GenerateSchema(Type type);
}
