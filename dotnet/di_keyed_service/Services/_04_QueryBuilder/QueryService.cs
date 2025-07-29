using di_keyed_service.Models;
using System.Linq.Expressions;

namespace di_keyed_service.Services._04_QueryBuilder
{
    public interface IQueryService
    {
        QueryResult ExecuteQuery(SampleModel request);
    }

    public class QueryService : IQueryService
    {
        private readonly IServiceProvider _serviceProvider;

        public QueryService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public QueryResult ExecuteQuery(SampleModel request)
        {
            var result = new QueryResult();
            var properties = request.GetType().GetProperties();

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(request);
                if (propertyValue == null) continue;

                // Try to process each model type
                ProcessModelA(property.Name, propertyValue, result);
                ProcessModelB(property.Name, propertyValue, result);
                ProcessModelC(property.Name, propertyValue, result);
                ProcessModelD(property.Name, propertyValue, result);
            }

            return result;
        }

        private void ProcessModelA(string propertyName, object value, QueryResult result)
        {
            var builder = _serviceProvider.GetKeyedService<IQueryPredicateBuilder<ModelA>>(propertyName);
            if (builder?.CanBuild(propertyName, value) == true)
            {
                var predicate = builder.BuildPredicate(value);
                var data = GetMockModelAData().AsQueryable().Where(predicate).ToList();
                result.ModelAResults.AddRange(data);
                result.AppliedPredicates[propertyName] = builder.GetPredicateDescription(value);
            }
        }

        private void ProcessModelB(string propertyName, object value, QueryResult result)
        {
            var builder = _serviceProvider.GetKeyedService<IQueryPredicateBuilder<ModelB>>(propertyName);
            if (builder?.CanBuild(propertyName, value) == true)
            {
                var predicate = builder.BuildPredicate(value);
                var data = GetMockModelBData().AsQueryable().Where(predicate).ToList();
                result.ModelBResults.AddRange(data);
                result.AppliedPredicates[propertyName] = builder.GetPredicateDescription(value);
            }
        }

        private void ProcessModelC(string propertyName, object value, QueryResult result)
        {
            var builder = _serviceProvider.GetKeyedService<IQueryPredicateBuilder<ModelC>>(propertyName);
            if (builder?.CanBuild(propertyName, value) == true)
            {
                var predicate = builder.BuildPredicate(value);
                var data = GetMockModelCData().AsQueryable().Where(predicate).ToList();
                result.ModelCResults.AddRange(data);
                result.AppliedPredicates[propertyName] = builder.GetPredicateDescription(value);
            }
        }

        private void ProcessModelD(string propertyName, object value, QueryResult result)
        {
            var builder = _serviceProvider.GetKeyedService<IQueryPredicateBuilder<ModelD>>(propertyName);
            if (builder?.CanBuild(propertyName, value) == true)
            {
                var predicate = builder.BuildPredicate(value);
                var data = GetMockModelDData().AsQueryable().Where(predicate).ToList();
                result.ModelDResults.AddRange(data);
                result.AppliedPredicates[propertyName] = builder.GetPredicateDescription(value);
            }
        }

        // Mock data methods (in real world, these would be repository calls)
        private static List<ModelA> GetMockModelAData()
        {
            return new List<ModelA>
            {
                new() { Id = 1, PropertyA = "Hello World", CreatedAt = DateTime.Now.AddDays(-1), IsActive = true },
                new() { Id = 2, PropertyA = "Test Data", CreatedAt = DateTime.Now.AddDays(-2), IsActive = true },
                new() { Id = 3, PropertyA = "Sample Entry", CreatedAt = DateTime.Now.AddDays(-3), IsActive = false }
            };
        }

        private static List<ModelB> GetMockModelBData()
        {
            return new List<ModelB>
            {
                new() { Id = 1, PropertyB = 10, Description = "First item", Amount = 100.50m },
                new() { Id = 2, PropertyB = 25, Description = "Second item", Amount = 250.75m },
                new() { Id = 3, PropertyB = 50, Description = "Third item", Amount = 500.00m }
            };
        }

        private static List<ModelC> GetMockModelCData()
        {
            return new List<ModelC>
            {
                new() { Id = 1, PropertyC = new[] { 1, 2, 3 }, Category = "Category A", Priority = 1 },
                new() { Id = 2, PropertyC = new[] { 3, 4, 5 }, Category = "Category B", Priority = 2 },
                new() { Id = 3, PropertyC = new[] { 5, 6, 7 }, Category = "Category C", Priority = 3 }
            };
        }

        private static List<ModelD> GetMockModelDData()
        {
            return new List<ModelD>
            {
                new() { Id = 1, PropertyD = true, Status = "Active", LastModified = DateTime.Now.AddHours(-1) },
                new() { Id = 2, PropertyD = false, Status = "Inactive", LastModified = DateTime.Now.AddHours(-2) },
                new() { Id = 3, PropertyD = true, Status = "Pending", LastModified = DateTime.Now.AddHours(-3) }
            };
        }
    }
}