using di_keyed_service.Models;

namespace di_keyed_service.Services._02_Generic
{
    public interface IGenericBaseService
    {
        string Key { get; }
        void RunGeneric(object param);
    }

    public interface IGenericService<T> : IGenericBaseService
    {
        void Run(T param);
    }
    public class GenericService1 : IGenericService<string>
    {
        public string Key => nameof(SampleModel.MyProperty1);

        public void Run(string param)
        {
            Console.WriteLine($"GenericService1 processing: {param}");
        }
        
        public void RunGeneric(object param)
        {
            if (param is string stringParam)
                Run(stringParam);
        }
    }

    public class GenericService2 : IGenericService<int?>
    {
        public string Key => nameof(SampleModel.MyProperty2);

        public void Run(int? param)
        {
            Console.WriteLine($"GenericService2 processing: {param}");
        }
        
        public void RunGeneric(object param)
        {
            Run(param as int?);
        }
    }
    public class GenericService3 : IGenericService<int[]>
    {
        public string Key => nameof(SampleModel.MyProperty3);

        public void Run(int[] param)
        {
            Console.WriteLine($"GenericService3 processing array with {param?.Length ?? 0} elements");
        }
        
        public void RunGeneric(object param)
        {
            if (param is int[] arrayParam)
                Run(arrayParam);
        }
    }
    public class GenericService4 : IGenericService<bool?>
    {
        public string Key => nameof(SampleModel.MyProperty4);

        public void Run(bool? param)
        {
            Console.WriteLine($"GenericService4 processing: {param}");
        }
        
        public void RunGeneric(object param)
        {
            Run(param as bool?);
        }
    }
}