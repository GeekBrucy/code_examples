using file_upload_zip.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Register zip services — one per library for comparison.
builder.Services.AddSingleton<SystemIoCompressionZipService>();
builder.Services.AddSingleton<SharpZipLibZipService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
