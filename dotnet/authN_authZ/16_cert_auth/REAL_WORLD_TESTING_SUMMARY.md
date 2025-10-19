# Real-World Testing with DbContext and Services

## Summary

This project now includes comprehensive real-world examples showing:

✅ **Entity Framework Core DbContext** usage
✅ **Service Layer** with business logic
✅ **Dependency Injection** in controllers
✅ **Unit Tests** with mocked dependencies
✅ **Integration Tests** with in-memory database
✅ **Complete documentation** on testing strategies

---

## Project Structure

```
API/
├── Controllers/
│   └── AuditController.cs          # Real-world controller with DbContext + Services
├── Data/
│   └── AppDbContext.cs              # EF Core DbContext
├── Models/
│   └── CertificateAuditLog.cs       # Entity model
└── Services/
    ├── IAuditService.cs             # Service interface
    └── AuditService.cs              # Service implementation

API.Tests/
├── AuditControllerUnitTests.cs      # Unit tests (mocked dependencies)
├── AuditControllerIntegrationTests.cs  # Integration tests (real database)
└── ...

Documentation/
├── TESTING_STRATEGIES.md            # Complete guide: when to mock vs when to use real
└── REAL_WORLD_TESTING_SUMMARY.md    # This file
```

---

## Key Concepts Demonstrated

### 1. **When to Mock** (Unit Tests)

**Mock:**
- ✅ DbContext (avoid database I/O)
- ✅ Service layer (test controller only)
- ✅ External dependencies (APIs, file system)

**Example:**
```csharp
// AuditControllerUnitTests.cs
private readonly Mock<AppDbContext> _mockContext;
private readonly Mock<IAuditService> _mockAuditService;

[Fact]
public async Task LogCurrentAuthentication_CallsAuditService()
{
    // Setup mock
    _mockAuditService
        .Setup(s => s.LogSuccessfulAuthenticationAsync(/*...*/))
        .Returns(Task.CompletedTask);

    // Act
    var result = await _controller.LogCurrentAuthentication();

    // Verify mock was called
    _mockAuditService.Verify(s => s.LogSuccessfulAuthenticationAsync(/*...*/), Times.Once);
}
```

**Why?** Tests controller logic in isolation, very fast, no database needed.

---

### 2. **When to Use Real Dependencies** (Integration Tests)

**Use Real:**
- ✅ DbContext with in-memory database
- ✅ Service implementations
- ✅ Complex LINQ queries
- ✅ Full workflow testing

**Example:**
```csharp
// AuditControllerIntegrationTests.cs
private readonly AppDbContext _context;          // REAL context
private readonly IAuditService _auditService;    // REAL service

public AuditControllerIntegrationTests()
{
    var options = new DbContextOptionsBuilder<AppDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString())  // Each test gets fresh DB
        .Options;

    _context = new AppDbContext(options);
    _auditService = new AuditService(_context, mockLogger.Object);
}

[Fact]
public async Task LogCurrentAuthentication_SavesAuditLogToDatabase()
{
    // Act
    await _controller.LogCurrentAuthentication();

    // Assert - verify data is actually in database
    var logs = await _context.CertificateAuditLogs.ToListAsync();
    logs.Should().HaveCount(1);
}
```

**Why?** Tests that data is actually saved, queries work correctly, full stack integration.

---

## Quick Decision Guide

### "Should I mock this dependency?"

**Ask yourself:**

1. **Am I testing the controller logic?**
   - YES → Mock the dependency
   - NO → Use real dependency (integration test)

2. **Does this involve database queries?**
   - YES → Integration test with in-memory database
   - NO → Unit test with mocks

3. **Is this a complex LINQ query?**
   - YES → Integration test (hard to mock IQueryable)
   - NO → Unit test is fine

4. **Am I testing error handling?**
   - YES → Unit test (mock to throw exceptions)

5. **Do I need to verify data persistence?**
   - YES → Integration test (check actual database state)

---

## Real-World Examples from This Project

### Example 1: Controller with Service Injection

**Controller:**
```csharp
public class AuditController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;

    public AuditController(AppDbContext context, IAuditService auditService, /*...*/)
    {
        _context = context;
        _auditService = auditService;
    }

    [HttpPost("log-current-auth")]
    public async Task<IActionResult> LogCurrentAuthentication()
    {
        await _auditService.LogSuccessfulAuthenticationAsync(/*...*/);
        return Ok();
    }
}
```

**Unit Test (Mock Service):**
```csharp
[Fact]
public async Task LogCurrentAuthentication_CallsAuditService()
{
    _mockAuditService
        .Setup(s => s.LogSuccessfulAuthenticationAsync(/*...*/))
        .Returns(Task.CompletedTask);

    await _controller.LogCurrentAuthentication();

    // Verify controller called the service correctly
    _mockAuditService.Verify(/*...*/);
}
```

**Integration Test (Real Service):**
```csharp
[Fact]
public async Task LogCurrentAuthentication_SavesAuditLogToDatabase()
{
    await _controller.LogCurrentAuthentication();

    // Verify data is actually in database
    var savedLog = await _context.CertificateAuditLogs.FirstOrDefaultAsync();
    savedLog.Should().NotBeNull();
}
```

---

### Example 2: Direct DbContext Usage

**Controller:**
```csharp
[HttpGet("my-logs")]
public async Task<IActionResult> GetMyAuditLogs()
{
    var logs = await _context.CertificateAuditLogs
        .Where(log => log.CertificateThumbprint == thumbprint)
        .OrderByDescending(log => log.AuthenticationTime)
        .Take(50)
        .ToListAsync();

    return Ok(logs);
}
```

**Unit Test (Test Validation Only):**
```csharp
[Fact]
public async Task GetMyAuditLogs_WithoutCertificate_ReturnsBadRequest()
{
    // Don't mock complex queries - just test validation
    SetupHttpContext(_controller, null);  // No certificate

    var result = await _controller.GetMyAuditLogs();
    result.Should().BeOfType<BadRequestObjectResult>();
}
```

**Integration Test (Test Query Logic):**
```csharp
[Fact]
public async Task GetMyAuditLogs_ReturnsOnlyCurrentCertificateLogs()
{
    // Add test data to real in-memory database
    await _context.CertificateAuditLogs.AddRangeAsync(/*...*/);
    await _context.SaveChangesAsync();

    // Execute query
    var result = await _controller.GetMyAuditLogs();

    // Verify query filtering works
    var okResult = result as OkObjectResult;
    // Assert on actual data returned...
}
```

---

## Test Statistics from This Project

After adding real-world examples:

| Test Type | Count | Purpose |
|-----------|-------|---------|
| **Unit Tests** | ~20 | Controller logic, validation, error handling |
| **Integration Tests** | ~15 | Data access, queries, full workflows |
| **Total Tests** | ~35 | Comprehensive coverage |

**Coverage:**
- ✅ All controller actions tested
- ✅ Both happy paths and error paths
- ✅ Service layer tested with real database
- ✅ Complex queries validated

---

## Key Takeaways

### 1. **Mocking is for Isolation**

**Purpose:** Test ONE component in complete isolation

**When:** Testing business logic, validation, error handling

**Benefits:**
- ⚡ Very fast (no I/O)
- 🎯 Focused (test only one thing)
- 🔁 Predictable (no external dependencies)

---

### 2. **Integration Tests are for Confidence**

**Purpose:** Test components working together

**When:** Testing data access, complex queries, full workflows

**Benefits:**
- ✅ Realistic (tests actual behavior)
- 🐛 Catches integration bugs
- 💪 Confidence in production behavior

---

### 3. **In-Memory Database is the Sweet Spot**

**Why use in-memory database?**
- ✅ Fast (faster than SQL Server)
- ✅ Isolated (each test gets own database)
- ✅ Real (uses actual EF Core)
- ✅ No cleanup needed

**Limitations:**
- ⚠️ Not 100% identical to production database
- ⚠️ Some features don't work (raw SQL, certain constraints)
- ⚠️ For critical features, consider testing against real database

---

### 4. **Test Both Layers**

**Unit Test the Controller:**
- Verify it calls services correctly
- Verify validation logic
- Verify response codes

**Integration Test the Full Stack:**
- Verify data is saved
- Verify queries work
- Verify workflows complete

**Both are valuable!** Don't skip either type.

---

## Running the Tests

```bash
# Run all tests
dotnet test

# Run only unit tests
dotnet test --filter FullyQualifiedName~UnitTests

# Run only integration tests
dotnet test --filter FullyQualifiedName~IntegrationTests

# Run tests with detailed output
dotnet test --logger "console;verbosity=detailed"
```

---

## Further Reading

See `TESTING_STRATEGIES.md` for:
- ✅ Detailed explanation of when to mock vs when to use real
- ✅ Complete examples of both approaches
- ✅ Decision trees and flowcharts
- ✅ Best practices and anti-patterns
- ✅ Troubleshooting common issues

---

## Questions Answered

### Q: "Should services and DbContext be mocked?"

**A:** It depends on what you're testing:

- **Unit tests:** YES, mock them (test controller in isolation)
- **Integration tests:** NO, use real implementations (test full stack)

### Q: "When do I use in-memory database vs mocked DbContext?"

**A:**

- **Mocked DbContext:** Unit tests (test logic without database)
- **In-memory database:** Integration tests (test queries work correctly)

### Q: "How do I test complex LINQ queries?"

**A:** Integration tests with in-memory database. Mocking IQueryable is extremely difficult.

### Q: "Do I need both unit and integration tests for the same method?"

**A:** Often yes! Example:

- **Unit test:** Verify controller validates input and calls service
- **Integration test:** Verify data is actually saved to database

They test different aspects of the same method.

---

## Conclusion

**The key is balance:**

- Write **many unit tests** for fast feedback on logic
- Write **strategic integration tests** for confidence in data access
- Use **in-memory database** for integration tests (sweet spot of speed + realism)

**Both types are valuable. Use appropriately based on what you're testing!**
