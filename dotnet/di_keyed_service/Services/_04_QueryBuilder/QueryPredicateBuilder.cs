using di_keyed_service.Models;
using System.Linq.Expressions;

namespace di_keyed_service.Services._04_QueryBuilder
{
    public interface IQueryPredicateBuilder<TModel>
    {
        string RequestPropertyName { get; }
        bool CanBuild(string propertyName, object value);
        Expression<Func<TModel, bool>> BuildPredicate(object value);
        string GetPredicateDescription(object value);
    }

    // Base class to reduce boilerplate
    public abstract class QueryPredicateBuilderBase<TModel> : IQueryPredicateBuilder<TModel>
    {
        public abstract string RequestPropertyName { get; }
        
        public virtual bool CanBuild(string propertyName, object value)
        {
            return propertyName == RequestPropertyName && value != null;
        }
        
        public abstract Expression<Func<TModel, bool>> BuildPredicate(object value);
        public abstract string GetPredicateDescription(object value);
    }

    // MyProperty1 -> ModelA.PropertyA (string contains)
    public class ModelAStringPredicateBuilder : QueryPredicateBuilderBase<ModelA>
    {
        public override string RequestPropertyName => nameof(SampleModel.MyProperty1);
        
        public override Expression<Func<ModelA, bool>> BuildPredicate(object value)
        {
            if (value is string stringValue && !string.IsNullOrEmpty(stringValue))
            {
                return model => model.PropertyA.Contains(stringValue);
            }
            return model => true; // No filter
        }
        
        public override string GetPredicateDescription(object value)
        {
            return $"ModelA.PropertyA contains '{value}'";
        }
    }

    // MyProperty2 -> ModelB.PropertyB (exact match or greater than)
    public class ModelBIntPredicateBuilder : QueryPredicateBuilderBase<ModelB>
    {
        public override string RequestPropertyName => nameof(SampleModel.MyProperty2);
        
        public override Expression<Func<ModelB, bool>> BuildPredicate(object value)
        {
            if (value is int intValue)
            {
                return model => model.PropertyB >= intValue;
            }
            return model => true; // No filter
        }
        
        public override string GetPredicateDescription(object value)
        {
            return $"ModelB.PropertyB >= {value}";
        }
    }

    // MyProperty3 -> ModelC.PropertyC (array intersection)
    public class ModelCArrayPredicateBuilder : QueryPredicateBuilderBase<ModelC>
    {
        public override string RequestPropertyName => nameof(SampleModel.MyProperty3);
        
        public override Expression<Func<ModelC, bool>> BuildPredicate(object value)
        {
            if (value is int[] arrayValue && arrayValue.Length > 0)
            {
                return model => model.PropertyC.Any(c => arrayValue.Contains(c));
            }
            return model => true; // No filter
        }
        
        public override string GetPredicateDescription(object value)
        {
            var array = value as int[] ?? Array.Empty<int>();
            return $"ModelC.PropertyC intersects with [{string.Join(", ", array)}]";
        }
    }

    // MyProperty4 -> ModelD.PropertyD (exact match)
    public class ModelDBoolPredicateBuilder : QueryPredicateBuilderBase<ModelD>
    {
        public override string RequestPropertyName => nameof(SampleModel.MyProperty4);
        
        public override Expression<Func<ModelD, bool>> BuildPredicate(object value)
        {
            if (value is bool boolValue)
            {
                return model => model.PropertyD == boolValue;
            }
            return model => true; // No filter
        }
        
        public override string GetPredicateDescription(object value)
        {
            return $"ModelD.PropertyD == {value}";
        }
    }
}