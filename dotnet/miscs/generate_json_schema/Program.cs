using generate_json_schema.Models;
using generate_json_schema.Services;

var outputDir = Path.Combine(AppContext.BaseDirectory, "output");
Directory.CreateDirectory(outputDir);

var services = new Dictionary<string, (IJsonSchemaService Service, string FileName)>
{
  ["STJ (net9 native)"] = (new StjSchemaService(), "zoo_stj.json"),
  ["NJsonSchema (net8+)"] = (new NJsonSchemaService(defaultDiscriminatorValue: "dog"), "zoo_njs.json"),
  ["JsonSchema.Net (net8+)"] = (new JsonSchemaNetService(), "zoo_jsn.json"),
};

foreach (var (name, (service, fileName)) in services)
{
  string schema;
  try
  {
    schema = service.GenerateSchema(typeof(Zoo));
  }
  catch (Exception ex)
  {
    // STJ throws when the same derived type appears under multiple discriminator keys.
    // The other services handle this case correctly.
    schema = $"// ERROR: {ex.GetType().Name}: {ex}";
    Console.WriteLine($"=== {name} ===");
    Console.WriteLine(schema);
  }

  var path = Path.Combine(outputDir, fileName);
  File.WriteAllText(path, schema);
  // Console.WriteLine($"=== {name} → {path} ===");
  // Console.WriteLine(schema);
  // Console.WriteLine();
}
