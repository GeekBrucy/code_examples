# Testing Strategies: Unit Tests vs Integration Tests

This document explains WHEN to mock and WHEN to use real implementations in your tests.

---

## Quick Answer: When to Mock vs When to Use Real

### ✅ **MOCK** in Unit Tests

| Dependency | Why Mock | How |
|------------|----------|-----|
| **DbContext** | Avoid database I/O; test controller logic only | `Mock<AppDbContext>` |
| **Service Layer** | Test controller, not service implementation | `Mock<IAuditService>` |
| **External APIs** | Unreliable, slow, may cost money | `Mock<IHttpClientFactory>` |
| **Logger** | Infrastructure concern, not business logic | `Mock<ILogger<T>>` |
| **Time** | Need predictable/controlled time | `Mock<ISystemClock>` |

### ✅ **USE REAL** in Integration Tests

| Component | Why Real | How |
|-----------|----------|-----|
| **DbContext** | Test actual data access and queries | `UseInMemoryDatabase()` |
| **Service Layer** | Test full stack integration | `new AuditService(realContext)` |
| **EF Core Queries** | LINQ queries are hard to mock | In-memory database |
| **Business Logic** | Verify complete workflows | Real implementations |

---

## The Testing Pyramid

```
        /\
       /  \
      / UI \ ← Few (manual or E2E tests)
     /______\
    /        \
   /Integration\ ← Some (test full stack with in-memory DB)
  /__________  _\
 /              \
/   Unit Tests   \ ← Many (fast, isolated, mocked dependencies)
/__________________\
```

**Goal:** Most tests should be unit tests (fast), fewer integration tests (slower but more realistic).

---

## Part 1: Unit Tests with Mocking

### What Are Unit Tests?

**Unit tests** test a SINGLE unit (class/method) in complete isolation.

**Characteristics:**
- ✅ **Fast** - No I/O, no database, no network
- ✅ **Isolated** - Only test the code in question
- ✅ **Predictable** - Same input = same output, always
- ✅ **Many** - Should be the bulk of your test suite

### When to Write Unit Tests

Use unit tests when testing:
- ✅ Controller logic (routing, validation, response shaping)
- ✅ Business logic (calculations, rules, decisions)
- ✅ Input validation
- ✅ Error handling
- ✅ Edge cases

### What to Mock in Unit Tests

#### Example: Testing AuditController

```csharp
public class AuditControllerUnitTests
{
    private readonly Mock<AppDbContext> _mockContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly AuditController _controller;

    public AuditControllerUnitTests()
    {
        // MOCK everything the controller depends on
        _mockContext = new Mock<AppDbContext>(/* options */);
        _mockAuditService = new Mock<IAuditService>();

        // Create controller with mocked dependencies
        _controller = new AuditController(
            _mockContext.Object,
            _mockAuditService.Object,
            Mock.Of<ILogger<AuditController>>());
    }
}
```

**Why mock the service?**

We're testing the **controller**, not the service. We want to verify:
- ✅ Controller calls the service with correct parameters
- ✅ Controller handles service responses correctly
- ✅ Controller handles service exceptions

We DON'T care about:
- ❌ How the service implements the logic (tested separately)
- ❌ Whether the service actually saves to database
- ❌ Database query performance

#### Example Test: Verify Method Call

```csharp
[Fact]
public async Task LogCurrentAuthentication_CallsServiceWithCorrectParameters()
{
    // Arrange
    _mockAuditService
        .Setup(s => s.LogSuccessfulAuthenticationAsync(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string?>(),
            It.IsAny<string?>(),
            It.IsAny<string?>()))
        .ReturnsAsync(Task.CompletedTask);

    // Act
    var result = await _controller.LogCurrentAuthentication();

    // Assert
    _mockAuditService.Verify(
        s => s.LogSuccessfulAuthenticationAsync(
            "CN=Test",              // Expected subject
            "ABC123",               // Expected thumbprint
            It.IsAny<string?>(),    // Don't care about these
            It.IsAny<string?>(),
            It.IsAny<string?>()),
        Times.Once);  // Verify called exactly once
}
```

**What this tests:**
- ✅ Controller calls the service
- ✅ Controller passes correct certificate data
- ✅ Controller calls it exactly once (not multiple times)

**What this doesn't test:**
- ❌ Whether data is actually saved (that's integration test)
- ❌ Service implementation (that's service unit test)

#### Example Test: Verify Error Handling

```csharp
[Fact]
public async Task LogCurrentAuthentication_WhenServiceFails_Returns500()
{
    // Arrange
    // Make the mock throw an exception
    _mockAuditService
        .Setup(s => s.LogSuccessfulAuthenticationAsync(/*...*/))
        .ThrowsAsync(new Exception("Database error"));

    // Act
    var result = await _controller.LogCurrentAuthentication();

    // Assert
    var statusCodeResult = result.Should().BeOfType<ObjectResult>().Subject;
    statusCodeResult.StatusCode.Should().Be(500);
}
```

**Why mock to throw?**
- ✅ We need to test controller's error handling
- ✅ Hard to make real service fail predictably
- ✅ Mocking lets us simulate any failure scenario

### What's Hard to Mock?

#### Problem: DbContext and LINQ Queries

```csharp
// This code is HARD to unit test with mocks
[HttpGet("my-logs")]
public async Task<IActionResult> GetMyAuditLogs()
{
    var logs = await _context.CertificateAuditLogs
        .Where(log => log.CertificateThumbprint == thumbprint)
        .OrderByDescending(log => log.AuthenticationTime)
        .Take(50)
        .ToListAsync();  // ← This requires complex mocking

    return Ok(logs);
}
```

**Why it's hard:**
- DbContext.DbSet returns IQueryable
- LINQ methods (Where, OrderByDescending, Take) need IQueryable support
- ToListAsync requires IAsyncEnumerable
- You'd need to mock: DbSet, IQueryable, IAsyncEnumerable, GetAsyncEnumerator...

**Solutions:**

1. **Unit test validation only:**
   ```csharp
   [Fact]
   public async Task GetMyAuditLogs_WithoutCertificate_ReturnsBadRequest()
   {
       // Test input validation, not the query
       SetupHttpContext(_controller, null);
       var result = await _controller.GetMyAuditLogs();
       result.Should().BeOfType<BadRequestObjectResult>();
   }
   ```

2. **Use integration test for query logic:**
   ```csharp
   // Integration test with real in-memory database
   [Fact]
   public async Task GetMyAuditLogs_ReturnsCorrectLogs()
   {
       // See integration test section below
   }
   ```

---

## Part 2: Integration Tests with Real Database

### What Are Integration Tests?

**Integration tests** test multiple components working together.

**Characteristics:**
- ✅ **Realistic** - Tests actual integration between components
- ✅ **Complete** - Tests full workflows
- ⚠️ **Slower** - Uses I/O (database, even if in-memory)
- ⚠️ **Fewer** - More expensive to write and maintain

### When to Write Integration Tests

Use integration tests when testing:
- ✅ Data access code (DbContext queries)
- ✅ Complex LINQ queries
- ✅ Entity relationships and constraints
- ✅ Full workflows (controller → service → database)
- ✅ Transaction behavior

### Using In-Memory Database

#### Why In-Memory Database?

**Advantages:**
- ✅ Fast (no disk I/O)
- ✅ Isolated (each test gets fresh database)
- ✅ No cleanup needed (disposed after test)
- ✅ Realistic (uses real EF Core)

**Limitations:**
- ⚠️ Not 100% identical to SQL Server/PostgreSQL
- ⚠️ Some features don't work (raw SQL, some constraints)
- ⚠️ Performance characteristics differ

#### Setup

```csharp
public class AuditControllerIntegrationTests
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;
    private readonly AuditController _controller;

    public AuditControllerIntegrationTests()
    {
        // Create REAL in-memory database
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())  // Unique per test
            .Options;

        _context = new AppDbContext(options);

        // Create REAL service with REAL context
        _auditService = new AuditService(
            _context,
            Mock.Of<ILogger<AuditService>>());

        // Create controller with REAL dependencies
        _controller = new AuditController(
            _context,
            _auditService,
            Mock.Of<ILogger<AuditController>>());
    }
}
```

**Key differences from unit tests:**
- ✅ Real AppDbContext (not mocked)
- ✅ Real AuditService (not mocked)
- ✅ Only logger is mocked (infrastructure, not logic)

#### Example: Testing Data Persistence

```csharp
[Fact]
public async Task LogCurrentAuthentication_SavesAuditLogToDatabase()
{
    // Arrange
    var initialCount = await _context.CertificateAuditLogs.CountAsync();
    initialCount.Should().Be(0);

    // Act
    var result = await _controller.LogCurrentAuthentication();

    // Assert
    // 1. Verify HTTP response
    result.Should().BeOfType<OkObjectResult>();

    // 2. Verify database was ACTUALLY updated
    var logsAfter = await _context.CertificateAuditLogs.ToListAsync();
    logsAfter.Should().HaveCount(1);

    // 3. Verify saved data is correct
    var savedLog = logsAfter.First();
    savedLog.CertificateThumbprint.Should().Be("ABC123");
    savedLog.IsSuccessful.Should().BeTrue();
}
```

**What this tests:**
- ✅ Full workflow: Controller → Service → Database
- ✅ Data is actually saved
- ✅ Data is saved correctly
- ✅ EF Core change tracking works

**What unit test couldn't verify:**
- ❌ Actual database save
- ❌ Entity configuration (keys, constraints)
- ❌ EF Core behavior

#### Example: Testing Complex Queries

```csharp
[Fact]
public async Task GetMyAuditLogs_ReturnsOnlyCurrentCertificateLogs()
{
    // Arrange
    // Add data to in-memory database
    await _context.CertificateAuditLogs.AddRangeAsync(new[]
    {
        new CertificateAuditLog {
            CertificateThumbprint = "ABC123",  // Current cert
            /*...*/
        },
        new CertificateAuditLog {
            CertificateThumbprint = "ABC123",  // Current cert
            /*...*/
        },
        new CertificateAuditLog {
            CertificateThumbprint = "DIFFERENT",  // Other cert
            /*...*/
        }
    });
    await _context.SaveChangesAsync();

    // Act
    var result = await _controller.GetMyAuditLogs();

    // Assert
    var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
    var value = okResult.Value as dynamic;

    // Verify only current certificate's logs returned
    ((int)value!.totalLogs).Should().Be(2);
}
```

**What this tests:**
- ✅ LINQ query logic (Where, OrderByDescending, Take)
- ✅ Filtering works correctly
- ✅ Query executes against real database

**Why integration test (not unit)?**
- ❌ Mocking IQueryable is extremely complex
- ❌ Mock wouldn't catch query bugs
- ✅ In-memory DB tests actual query execution

#### Example: Testing Aggregations

```csharp
[Fact]
public async Task GetStatistics_CalculatesCorrectAggregations()
{
    // Arrange
    await _context.CertificateAuditLogs.AddRangeAsync(/*...*/);
    await _context.SaveChangesAsync();

    // Act
    var result = await _controller.GetStatistics();

    // Assert
    var stats = (result as OkObjectResult)!.Value as dynamic;
    ((int)stats!.totalLogs).Should().Be(4);
    ((int)stats.uniqueCertificates).Should().Be(3);
    ((double)stats.successRate).Should().BeApproximately(75.0, 0.1);
}
```

**What this tests:**
- ✅ GroupBy works correctly
- ✅ Distinct count is accurate
- ✅ Percentage calculation is correct
- ✅ Complex aggregations execute properly

---

## Part 3: Practical Decision Guide

### Decision Tree: Unit Test or Integration Test?

```
Are you testing...

├─ Input validation?
│  └─ Unit Test (mock dependencies)
│
├─ Error handling?
│  └─ Unit Test (mock to throw exceptions)
│
├─ HTTP response codes?
│  └─ Unit Test (verify controller behavior)
│
├─ Data access (queries, saves)?
│  └─ Integration Test (real database)
│
├─ Complex LINQ queries?
│  └─ Integration Test (hard to mock IQueryable)
│
├─ Full workflow (controller → service → DB)?
│  └─ Integration Test (test complete stack)
│
└─ Business logic calculations?
   └─ Unit Test if no database needed
   └─ Integration Test if database required
```

### Real-World Examples

#### Scenario 1: Validate Input

```csharp
// Controller
[HttpGet("recent")]
public async Task<IActionResult> GetRecentAuditLogs(int count = 100)
{
    if (count < 1 || count > 1000)
        return BadRequest(new { error = "Count must be between 1 and 1000" });

    var logs = await _auditService.GetRecentAuditLogsAsync(count);
    return Ok(logs);
}

// ✅ UNIT TEST - No need for real database
[Theory]
[InlineData(0)]     // Too small
[InlineData(-1)]    // Negative
[InlineData(1001)]  // Too large
public async Task GetRecentAuditLogs_WithInvalidCount_ReturnsBadRequest(int count)
{
    // Mock service (not called for invalid input)
    var result = await _controller.GetRecentAuditLogs(count);
    result.Should().BeOfType<BadRequestObjectResult>();

    // Verify service was NEVER called
    _mockAuditService.Verify(
        s => s.GetRecentAuditLogsAsync(It.IsAny<int>()),
        Times.Never);
}
```

**Why unit test?**
- ✅ Testing controller logic only
- ✅ No database needed
- ✅ Fast, simple

#### Scenario 2: Complex Query

```csharp
// Controller
[HttpGet("statistics")]
public async Task<IActionResult> GetStatistics()
{
    var stats = await _context.CertificateAuditLogs
        .GroupBy(log => log.IsSuccessful)
        .Select(group => new { isSuccessful = group.Key, count = group.Count() })
        .ToListAsync();

    return Ok(stats);
}

// ✅ INTEGRATION TEST - Test actual query
[Fact]
public async Task GetStatistics_CalculatesCorrectly()
{
    // Add test data to real in-memory database
    await _context.CertificateAuditLogs.AddRangeAsync(/*...*/);
    await _context.SaveChangesAsync();

    // Execute query against real database
    var result = await _controller.GetStatistics();

    // Verify aggregations
    var stats = (result as OkObjectResult)!.Value;
    // Assert on aggregation results...
}
```

**Why integration test?**
- ❌ GroupBy, Select, ToListAsync hard to mock
- ✅ Tests actual EF Core query execution
- ✅ Catches query bugs

#### Scenario 3: Service Call

```csharp
// Controller
[HttpPost("log")]
public async Task<IActionResult> LogAuthentication()
{
    await _auditService.LogSuccessfulAuthenticationAsync(/*...*/);
    return Ok();
}

// ✅ UNIT TEST - Verify controller calls service
[Fact]
public async Task LogAuthentication_CallsServiceWithCorrectParams()
{
    _mockAuditService
        .Setup(s => s.LogSuccessfulAuthenticationAsync(/*...*/))
        .Returns(Task.CompletedTask);

    var result = await _controller.LogAuthentication();

    _mockAuditService.Verify(
        s => s.LogSuccessfulAuthenticationAsync(
            "CN=Test",
            "ABC123",
            /*...*/),
        Times.Once);
}

// ✅ INTEGRATION TEST - Verify data is actually saved
[Fact]
public async Task LogAuthentication_SavesToDatabase()
{
    var result = await _controller.LogAuthentication();

    var savedLog = await _context.CertificateAuditLogs.FirstOrDefaultAsync();
    savedLog.Should().NotBeNull();
    savedLog!.CertificateThumbprint.Should().Be("ABC123");
}
```

**Both tests are valuable:**
- Unit test: Verifies controller behavior
- Integration test: Verifies end-to-end workflow

---

## Part 4: Best Practices

### Unit Test Best Practices

✅ **DO:**
- Mock external dependencies (DbContext, services, APIs)
- Test one thing per test
- Use descriptive test names
- Verify mock calls when testing delegation
- Test error paths with mocked exceptions

❌ **DON'T:**
- Access real database
- Access network/files
- Use Thread.Sleep or real time
- Make tests dependent on each other
- Test framework code (EF Core, ASP.NET)

### Integration Test Best Practices

✅ **DO:**
- Use in-memory database for speed
- Give each test a unique database (Guid.NewGuid())
- Test complex queries and aggregations
- Test full workflows
- Verify database state after operations

❌ **DON'T:**
- Share database between tests
- Use real SQL Server/PostgreSQL (too slow)
- Test simple validation (use unit tests)
- Rely on test execution order

### Coverage Guidelines

**Aim for:**
- 80%+ unit test coverage
- Critical paths have integration tests
- Every public method has at least one test
- All error paths tested

**Don't:**
- Chase 100% coverage
- Test getters/setters
- Test framework code
- Over-test simple code

---

## Summary Table

| Aspect | Unit Tests | Integration Tests |
|--------|------------|-------------------|
| **Speed** | Very fast (< 1ms) | Slower (10-100ms) |
| **Dependencies** | All mocked | Real (in-memory DB) |
| **Isolation** | Complete | Partial |
| **What to test** | Controller logic, validation, error handling | Queries, persistence, full workflows |
| **Quantity** | Many (70-80% of tests) | Fewer (20-30% of tests) |
| **When they fail** | Code logic bug | Integration bug, query bug |
| **Example** | Verify method called with params | Verify data saved to database |

---

## Conclusion

**Rule of Thumb:**

- **Mock** when testing logic/behavior
- **Use real** when testing data access

**Remember:**
- Unit tests = Fast feedback on logic
- Integration tests = Confidence in data access
- Both are valuable, use appropriately

**The key is balance:** Write many fast unit tests, supplement with strategic integration tests for critical data access paths.
