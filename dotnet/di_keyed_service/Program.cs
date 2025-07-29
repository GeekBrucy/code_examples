using di_keyed_service.Services._01_Fundamental;
using di_keyed_service.Services._02_Generic;
using di_keyed_service.Services._03_PropertyProcessor;
using di_keyed_service.Services._04_QueryBuilder;
using di_keyed_service.Models;

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
// Register generic services as keyed services using property names
builder.Services.AddKeyedTransient<IGenericBaseService, GenericService1>(nameof(SampleModel.MyProperty1));
builder.Services.AddKeyedTransient<IGenericBaseService, GenericService2>(nameof(SampleModel.MyProperty2));
builder.Services.AddKeyedTransient<IGenericBaseService, GenericService3>(nameof(SampleModel.MyProperty3));
builder.Services.AddKeyedTransient<IGenericBaseService, GenericService4>(nameof(SampleModel.MyProperty4));

// Register property processors as keyed services
builder.Services.AddKeyedTransient<IPropertyProcessor, StringPropertyProcessor>(nameof(SampleModel.MyProperty1));
builder.Services.AddKeyedTransient<IPropertyProcessor, IntPropertyProcessor>(nameof(SampleModel.MyProperty2));
builder.Services.AddKeyedTransient<IPropertyProcessor, IntArrayPropertyProcessor>(nameof(SampleModel.MyProperty3));
builder.Services.AddKeyedTransient<IPropertyProcessor, BoolPropertyProcessor>(nameof(SampleModel.MyProperty4));

// Register query predicate builders as keyed services
builder.Services.AddKeyedTransient<IQueryPredicateBuilder<ModelA>, ModelAStringPredicateBuilder>(nameof(SampleModel.MyProperty1));
builder.Services.AddKeyedTransient<IQueryPredicateBuilder<ModelB>, ModelBIntPredicateBuilder>(nameof(SampleModel.MyProperty2));
builder.Services.AddKeyedTransient<IQueryPredicateBuilder<ModelC>, ModelCArrayPredicateBuilder>(nameof(SampleModel.MyProperty3));
builder.Services.AddKeyedTransient<IQueryPredicateBuilder<ModelD>, ModelDBoolPredicateBuilder>(nameof(SampleModel.MyProperty4));

// Register the query service
builder.Services.AddTransient<IQueryService, QueryService>();

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
