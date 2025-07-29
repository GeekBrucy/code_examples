using di_keyed_service.Models;

namespace di_keyed_service.Services._03_PropertyProcessor
{
    public interface IPropertyProcessor
    {
        string PropertyName { get; }
        void ProcessProperty(string propertyName, object value);
        bool CanProcess(string propertyName);
    }

    public class StringPropertyProcessor : IPropertyProcessor
    {
        public string PropertyName => nameof(SampleModel.MyProperty1);
        
        public bool CanProcess(string propertyName) => propertyName == PropertyName;
        
        public void ProcessProperty(string propertyName, object value)
        {
            if (CanProcess(propertyName) && value is string stringValue)
            {
                Console.WriteLine($"StringPropertyProcessor processing {propertyName}: {stringValue}");
            }
        }
    }

    public class IntPropertyProcessor : IPropertyProcessor
    {
        public string PropertyName => nameof(SampleModel.MyProperty2);
        
        public bool CanProcess(string propertyName) => propertyName == PropertyName;
        
        public void ProcessProperty(string propertyName, object value)
        {
            if (CanProcess(propertyName))
            {
                Console.WriteLine($"IntPropertyProcessor processing {propertyName}: {value}");
            }
        }
    }

    public class IntArrayPropertyProcessor : IPropertyProcessor
    {
        public string PropertyName => nameof(SampleModel.MyProperty3);
        
        public bool CanProcess(string propertyName) => propertyName == PropertyName;
        
        public void ProcessProperty(string propertyName, object value)
        {
            if (CanProcess(propertyName) && value is int[] arrayValue)
            {
                Console.WriteLine($"IntArrayPropertyProcessor processing {propertyName}: [{string.Join(", ", arrayValue)}]");
            }
        }
    }

    public class BoolPropertyProcessor : IPropertyProcessor
    {
        public string PropertyName => nameof(SampleModel.MyProperty4);
        
        public bool CanProcess(string propertyName) => propertyName == PropertyName;
        
        public void ProcessProperty(string propertyName, object value)
        {
            if (CanProcess(propertyName))
            {
                Console.WriteLine($"BoolPropertyProcessor processing {propertyName}: {value}");
            }
        }
    }
}