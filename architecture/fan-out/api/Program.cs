using api.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Fan-out Example 1: Task.WhenAll-based worker service
builder.Services.AddScoped<IWorkerService, WorkerService>();

// Fan-out Example 2: Channel-based producer/consumer fan-out
// Registered as Singleton so the controller and BackgroundService share the same instance
builder.Services.AddSingleton<ChannelFanOutService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ChannelFanOutService>());

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
