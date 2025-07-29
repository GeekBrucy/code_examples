using di_keyed_service.Services._01_Fundamental;
using di_keyed_service.Services._02_Generic;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddKeyedTransient<IBasic, BasicService1>("Basic1");
builder.Services.AddKeyedTransient<IBasic, BasicService2>("Basic2");

// Also register as non-keyed for IEnumerable<IBasic> injection
builder.Services.AddTransient<IBasic, BasicService1>();
builder.Services.AddTransient<IBasic, BasicService2>();

// Register generic services with specific type parameters
builder.Services.AddTransient<IGenericBaseService, GenericService1>();
builder.Services.AddTransient<IGenericBaseService, GenericService2>();
builder.Services.AddTransient<IGenericBaseService, GenericService3>();
builder.Services.AddTransient<IGenericBaseService, GenericService4>();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

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
