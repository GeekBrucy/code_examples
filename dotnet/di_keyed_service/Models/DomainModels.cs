namespace di_keyed_service.Models
{
    // Target domain models that will be queried
    public class ModelA
    {
        public int Id { get; set; }
        public string PropertyA { get; set; } // Maps to SampleModel.MyProperty1
        public DateTime CreatedAt { get; set; }
        public bool IsActive { get; set; }
    }

    public class ModelB
    {
        public int Id { get; set; }
        public int? PropertyB { get; set; } // Maps to SampleModel.MyProperty2
        public string Description { get; set; }
        public decimal Amount { get; set; }
    }

    public class ModelC
    {
        public int Id { get; set; }
        public int[] PropertyC { get; set; } // Maps to SampleModel.MyProperty3
        public string Category { get; set; }
        public int Priority { get; set; }
    }

    public class ModelD
    {
        public int Id { get; set; }
        public bool? PropertyD { get; set; } // Maps to SampleModel.MyProperty4
        public string Status { get; set; }
        public DateTime LastModified { get; set; }
    }

    // Represents the final query result with combined data
    public class QueryResult
    {
        public List<ModelA> ModelAResults { get; set; } = new();
        public List<ModelB> ModelBResults { get; set; } = new();
        public List<ModelC> ModelCResults { get; set; } = new();
        public List<ModelD> ModelDResults { get; set; } = new();
        public Dictionary<string, string> AppliedPredicates { get; set; } = new();
    }
}