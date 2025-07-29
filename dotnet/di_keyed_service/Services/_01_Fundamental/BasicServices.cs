namespace di_keyed_service.Services._01_Fundamental
{
    public interface IBasic
    {
        string Key { get; }
        void Run();
    }

    public class BasicService1 : IBasic
    {
        public string Key => "Basic1";
        
        public void Run()
        {
            Console.WriteLine(new string('@', 50));
            Console.WriteLine("From BasicService1");
            Console.WriteLine(new string('@', 50));
        }
    }
    public class BasicService2 : IBasic
    {
        public string Key => "Basic2";
        
        public void Run()
        {
            Console.WriteLine(new string('@', 50));
            Console.WriteLine("From BasicService2");
            Console.WriteLine(new string('@', 50));
        }
    }
}