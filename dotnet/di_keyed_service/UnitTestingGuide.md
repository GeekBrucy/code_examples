# Unit Testing Guide for Query Builder Pattern

## Overview

This guide covers how to effectively unit test the automated query builder pattern that uses keyed dependency injection to map request properties to database query predicates.

## Testing Strategy

### 1. **Three-Layer Testing Approach**

```
┌─────────────────────┐
│   Unit Tests        │  ← Test individual builders in isolation
│   (Fast, Focused)   │
├─────────────────────┤
│   Integration Tests │  ← Test QueryService orchestration  
│   (Medium Speed)    │
├─────────────────────┤
│   Registration Tests│  ← Test DI container setup
│   (Fast, Setup)     │
└─────────────────────┘
```

### 2. **Test Pyramid Benefits**
- **Fast feedback**: Majority of tests are fast unit tests
- **Clear failures**: Failed tests point to specific builders
- **Parallel development**: Teams can test builders independently
- **Easy maintenance**: Small, focused test classes

## Individual Builder Tests

### Basic Builder Test Template

```csharp
[TestFixture]
public class ModelAStringPredicateBuilderTests
{
    private ModelAStringPredicateBuilder _builder;
    private List<ModelA> _testData;

    [SetUp]
    public void Setup()
    {
        _builder = new ModelAStringPredicateBuilder();
        _testData = new List<ModelA>
        {
            new() { Id = 1, PropertyA = "Hello World", IsActive = true },
            new() { Id = 2, PropertyA = "Test Data", IsActive = true },
            new() { Id = 3, PropertyA = "Say Hello", IsActive = false }
        };
    }

    [Test]
    public void BuildPredicate_WithValidString_ReturnsMatchingRecords()
    {
        // Arrange
        var searchValue = "Hello";

        // Act
        var predicate = _builder.BuildPredicate(searchValue);
        var results = _testData.AsQueryable().Where(predicate).ToList();

        // Assert
        Assert.AreEqual(2, results.Count);
        Assert.IsTrue(results.All(x => x.PropertyA.Contains("Hello")));
        Assert.AreEqual(new[] { 1, 3 }, results.Select(x => x.Id).OrderBy(x => x));
    }

    [Test]
    public void CanBuild_WithCorrectPropertyName_ReturnsTrue()
    {
        // Act & Assert
        Assert.IsTrue(_builder.CanBuild(nameof(SampleModel.MyProperty1), "test"));
    }

    [Test]
    public void CanBuild_WithIncorrectPropertyName_ReturnsFalse()
    {
        // Act & Assert
        Assert.IsFalse(_builder.CanBuild("WrongProperty", "test"));
    }

    [Test]
    public void GetPredicateDescription_ReturnsCorrectFormat()
    {
        // Act
        var description = _builder.GetPredicateDescription("Hello");

        // Assert
        Assert.AreEqual("ModelA.PropertyA contains 'Hello'", description);
    }
}
```

### Edge Cases Testing

```csharp
[TestCase(null, ExpectedResult = 3, Description = "Null input should return all records")]
[TestCase("", ExpectedResult = 3, Description = "Empty string should return all records")]
[TestCase("NonExistent", ExpectedResult = 0, Description = "Non-matching string should return no records")]
[TestCase("HELLO", ExpectedResult = 0, Description = "Case-sensitive search should not match")]
[TestCase("Hello", ExpectedResult = 2, Description = "Valid search should return matching records")]
public int BuildPredicate_EdgeCases_HandlesCorrectly(string input)
{
    // Act
    var predicate = _builder.BuildPredicate(input);
    var results = _testData.AsQueryable().Where(predicate).ToList();

    // Assert
    return results.Count;
}

[Test]
public void CanBuild_WithNullValue_ReturnsFalse()
{
    // Act & Assert
    Assert.IsFalse(_builder.CanBuild(nameof(SampleModel.MyProperty1), null));
}
```

### Array/Collection Builder Tests

```csharp
[TestFixture]
public class ModelCArrayPredicateBuilderTests
{
    [Test]
    public void BuildPredicate_ArrayIntersection_FindsMatchingRecords()
    {
        // Arrange
        var builder = new ModelCArrayPredicateBuilder();
        var searchArray = new[] { 3, 4 };
        var testData = new List<ModelC>
        {
            new() { Id = 1, PropertyC = new[] { 1, 2, 3 } },    // Should match (contains 3)
            new() { Id = 2, PropertyC = new[] { 3, 4, 5 } },    // Should match (contains 3,4)
            new() { Id = 3, PropertyC = new[] { 6, 7, 8 } }     // Should not match
        };

        // Act
        var predicate = builder.BuildPredicate(searchArray);
        var results = testData.AsQueryable().Where(predicate).ToList();

        // Assert
        Assert.AreEqual(2, results.Count);
        Assert.AreEqual(new[] { 1, 2 }, results.Select(x => x.Id).OrderBy(x => x));
    }

    [Test]
    public void BuildPredicate_EmptyArray_ReturnsAllRecords()
    {
        // Arrange
        var builder = new ModelCArrayPredicateBuilder();
        var emptyArray = Array.Empty<int>();

        // Act
        var predicate = builder.BuildPredicate(emptyArray);

        // Assert - Should return true for all records (no filter)
        Assert.IsTrue(predicate.Compile()(new ModelC { PropertyC = new[] { 1, 2, 3 } }));
    }
}
```

## Integration Tests

### QueryService Orchestration Tests

```csharp
[TestFixture]
public class QueryServiceTests
{
    private Mock<IServiceProvider> _mockServiceProvider;
    private QueryService _queryService;

    [SetUp]
    public void Setup()
    {
        _mockServiceProvider = new Mock<IServiceProvider>();
        _queryService = new QueryService(_mockServiceProvider.Object);
    }

    [Test]
    public void ExecuteQuery_WithMultipleProperties_CallsCorrectBuilders()
    {
        // Arrange
        var mockBuilderA = new Mock<IQueryPredicateBuilder<ModelA>>();
        var mockBuilderB = new Mock<IQueryPredicateBuilder<ModelB>>();
        
        mockBuilderA.Setup(x => x.CanBuild("MyProperty1", "test")).Returns(true);
        mockBuilderA.Setup(x => x.BuildPredicate("test")).Returns(m => m.PropertyA.Contains("test"));
        mockBuilderA.Setup(x => x.GetPredicateDescription("test")).Returns("Test description");
        
        _mockServiceProvider.Setup(x => x.GetKeyedService<IQueryPredicateBuilder<ModelA>>("MyProperty1"))
                           .Returns(mockBuilderA.Object);
        _mockServiceProvider.Setup(x => x.GetKeyedService<IQueryPredicateBuilder<ModelB>>("MyProperty2"))
                           .Returns(mockBuilderB.Object);

        var request = new SampleModel 
        { 
            MyProperty1 = "test", 
            MyProperty2 = 10 
        };

        // Act
        var result = _queryService.ExecuteQuery(request);

        // Assert
        mockBuilderA.Verify(x => x.CanBuild("MyProperty1", "test"), Times.Once);
        mockBuilderA.Verify(x => x.BuildPredicate("test"), Times.Once);
        Assert.IsTrue(result.AppliedPredicates.ContainsKey("MyProperty1"));
    }

    [Test]
    public void ExecuteQuery_WithNullProperties_SkipsNullValues()
    {
        // Arrange
        var request = new SampleModel 
        { 
            MyProperty1 = null,  // Should be skipped
            MyProperty2 = 10     // Should be processed
        };

        // Act
        var result = _queryService.ExecuteQuery(request);

        // Assert
        _mockServiceProvider.Verify(
            x => x.GetKeyedService<IQueryPredicateBuilder<ModelA>>("MyProperty1"), 
            Times.Never);
    }
}
```

## Service Registration Tests

### DI Container Setup Tests

```csharp
[TestFixture]
public class ServiceRegistrationTests
{
    [Test]
    public void ServiceProvider_CanResolveAllBuilders()
    {
        // Arrange
        var services = new ServiceCollection();
        RegisterQueryBuilders(services); // Your actual registration method
        var provider = services.BuildServiceProvider();

        // Act & Assert
        var builderA = provider.GetKeyedService<IQueryPredicateBuilder<ModelA>>(nameof(SampleModel.MyProperty1));
        var builderB = provider.GetKeyedService<IQueryPredicateBuilder<ModelB>>(nameof(SampleModel.MyProperty2));
        var builderC = provider.GetKeyedService<IQueryPredicateBuilder<ModelC>>(nameof(SampleModel.MyProperty3));
        var builderD = provider.GetKeyedService<IQueryPredicateBuilder<ModelD>>(nameof(SampleModel.MyProperty4));

        Assert.IsNotNull(builderA);
        Assert.IsNotNull(builderB);
        Assert.IsNotNull(builderC);
        Assert.IsNotNull(builderD);
        
        Assert.IsInstanceOf<ModelAStringPredicateBuilder>(builderA);
        Assert.IsInstanceOf<ModelBIntPredicateBuilder>(builderB);
        Assert.IsInstanceOf<ModelCArrayPredicateBuilder>(builderC);
        Assert.IsInstanceOf<ModelDBoolPredicateBuilder>(builderD);
    }

    [Test]
    public void ServiceProvider_QueryService_CanBeResolved()
    {
        // Arrange
        var services = new ServiceCollection();
        RegisterAllServices(services);
        var provider = services.BuildServiceProvider();

        // Act
        var queryService = provider.GetService<IQueryService>();

        // Assert
        Assert.IsNotNull(queryService);
        Assert.IsInstanceOf<QueryService>(queryService);
    }
}
```

## Test Structure Organization

### Recommended Folder Structure

```
Tests/
├── Unit/
│   ├── Builders/
│   │   ├── ModelAStringPredicateBuilderTests.cs
│   │   ├── ModelBIntPredicateBuilderTests.cs
│   │   ├── ModelCArrayPredicateBuilderTests.cs
│   │   └── ModelDBoolPredicateBuilderTests.cs
│   └── Base/
│       └── QueryPredicateBuilderBaseTests.cs
├── Integration/
│   └── QueryServiceTests.cs
├── Registration/
│   └── ServiceRegistrationTests.cs
└── TestHelpers/
    ├── TestDataBuilder.cs
    └── MockServiceProviderBuilder.cs
```

### Test Helper Classes

```csharp
public static class TestDataBuilder
{
    public static List<ModelA> CreateModelAData(int count = 10)
    {
        return Enumerable.Range(1, count)
            .Select(i => new ModelA 
            { 
                Id = i, 
                PropertyA = $"Test Data {i}", 
                IsActive = i % 2 == 0 
            })
            .ToList();
    }
}

public class MockServiceProviderBuilder
{
    private readonly Mock<IServiceProvider> _mockProvider = new();

    public MockServiceProviderBuilder WithBuilder<TModel>(string key, IQueryPredicateBuilder<TModel> builder)
    {
        _mockProvider.Setup(x => x.GetKeyedService<IQueryPredicateBuilder<TModel>>(key))
                    .Returns(builder);
        return this;
    }

    public IServiceProvider Build() => _mockProvider.Object;
}
```

## Best Practices

### 1. **Test Naming Conventions**
```csharp
// Pattern: MethodName_Scenario_ExpectedResult
[Test]
public void BuildPredicate_WithValidString_ReturnsMatchingRecords() { }

[Test]
public void BuildPredicate_WithNullInput_ReturnsAllRecords() { }

[Test]
public void CanBuild_WithIncorrectPropertyName_ReturnsFalse() { }
```

### 2. **AAA Pattern (Arrange, Act, Assert)**
```csharp
[Test]
public void Example_Test()
{
    // Arrange - Set up test data and dependencies
    var builder = new ModelAStringPredicateBuilder();
    var testValue = "Hello";

    // Act - Execute the method under test
    var result = builder.BuildPredicate(testValue);

    // Assert - Verify the expected outcome
    Assert.IsNotNull(result);
}
```

### 3. **Data-Driven Tests for Edge Cases**
```csharp
[TestCase("", ExpectedResult = 0)]
[TestCase("Test", ExpectedResult = 1)]
[TestCase("NonExistent", ExpectedResult = 0)]
public int BuildPredicate_VariousInputs_ReturnsExpectedCount(string input)
{
    // Test implementation
}
```

### 4. **Mock External Dependencies**
```csharp
// Mock IServiceProvider instead of setting up full DI container
var mockProvider = new Mock<IServiceProvider>();
var queryService = new QueryService(mockProvider.Object);
```

### 5. **Test Performance for Large Datasets**
```csharp
[Test]
public void BuildPredicate_WithLargeDataset_PerformsEfficiently()
{
    // Arrange
    var largeDataset = GenerateLargeTestData(10000);
    var builder = new ModelAStringPredicateBuilder();
    
    // Act
    var stopwatch = Stopwatch.StartNew();
    var predicate = builder.BuildPredicate("search");
    var results = largeDataset.AsQueryable().Where(predicate).ToList();
    stopwatch.Stop();
    
    // Assert
    Assert.Less(stopwatch.ElapsedMilliseconds, 100, "Query should complete within 100ms");
}
```

## Benefits of This Testing Approach

### ✅ **Maintainable**
- Each builder has its own focused test class
- Easy to locate and fix failing tests
- No giant test classes

### ✅ **Fast Execution**
- Unit tests run in milliseconds
- No database or heavy DI setup for most tests
- Parallel test execution possible

### ✅ **Comprehensive Coverage**
- Edge cases covered with parameterized tests
- Integration points tested separately
- Registration validation included

### ✅ **Developer Friendly**
- Clear test failures point to exact issues
- Easy to write tests for new builders
- Consistent testing patterns

### ✅ **Scalable**
- Adding 100 new properties = adding 100 focused test classes
- No need to modify existing test files
- Team can work on tests in parallel

## Conclusion

This testing approach transforms a potentially complex testing scenario (100+ properties) into manageable, focused tests. Each builder gets its own test class, making the codebase maintainable and the tests reliable.

The key is treating each predicate builder as an independent unit with clear inputs and outputs, while testing the orchestration separately through integration tests.