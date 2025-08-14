# Attribute-Based Access Control (ABAC)

## Overview
Attribute-Based Access Control (ABAC) is a flexible authorization model that makes access decisions based on attributes of the user, resource, action, and environment. Unlike RBAC or ACL, ABAC uses policies to evaluate multiple attributes dynamically, enabling fine-grained, context-aware authorization decisions.

## Core Concepts

### 1. ABAC Components

#### Attributes
- **Subject Attributes**: Properties of the user (role, department, clearance level, location)
- **Resource Attributes**: Properties of the protected resource (classification, owner, creation date)
- **Action Attributes**: Properties of the requested action (read, write, delete, print)
- **Environment Attributes**: Contextual information (time, location, network, device trust)

#### Policies
- Rules that define when access should be granted or denied
- Written in policy languages (XACML, JSON, custom DSL)
- Can be complex logical expressions combining multiple attributes
- Support for obligations and advice

#### Policy Decision Point (PDP)
- Evaluates policies against attribute values
- Returns permit, deny, or indeterminate decisions
- Can provide obligations (actions that must be performed)

#### Policy Information Point (PIP)
- Provides attribute values to the PDP
- Can fetch attributes from multiple sources
- Caches attribute values for performance

#### Policy Enforcement Point (PEP)
- Intercepts access requests
- Queries PDP for authorization decisions
- Enforces the decision and any obligations

### 2. ABAC vs Other Models

#### Advantages
- **Flexibility**: Complex policies with multiple conditions
- **Context-aware**: Considers environmental factors
- **Fine-grained**: Detailed control over access decisions
- **Dynamic**: Policies can adapt to changing conditions
- **Scalable**: Centralized policy management

#### Disadvantages
- **Complexity**: More difficult to design and implement
- **Performance**: Policy evaluation can be expensive
- **Debugging**: Hard to troubleshoot policy conflicts
- **Management**: Requires sophisticated tooling

## .NET ABAC Implementation

### 1. ABAC Data Models

```csharp
// Attribute definitions
public class AttributeValue
{
    public string Name { get; set; }
    public object Value { get; set; }
    public AttributeType Type { get; set; }
    public AttributeCategory Category { get; set; }
}

public enum AttributeType
{
    String,
    Integer,
    Boolean,
    DateTime,
    Collection
}

public enum AttributeCategory
{
    Subject,
    Resource,
    Action,
    Environment
}

// Policy models
public class Policy
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public string Target { get; set; } // JSON expression defining when policy applies
    public List<Rule> Rules { get; set; } = new();
    public bool IsActive { get; set; } = true;
    public int Priority { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string CreatedBy { get; set; }
}

public class Rule
{
    public int Id { get; set; }
    public int PolicyId { get; set; }
    public string Condition { get; set; } // JSON expression
    public Effect Effect { get; set; } // Permit or Deny
    public List<Obligation> Obligations { get; set; } = new();
    public int Order { get; set; }
    
    // Navigation property
    public virtual Policy Policy { get; set; }
}

public class Obligation
{
    public int Id { get; set; }
    public int RuleId { get; set; }
    public string Type { get; set; } // Log, Notify, Audit, etc.
    public string Parameters { get; set; } // JSON parameters
    
    // Navigation property
    public virtual Rule Rule { get; set; }
}

public enum Effect
{
    Permit,
    Deny
}

// Authorization request context
public class AuthorizationRequest
{
    public Dictionary<string, AttributeValue> SubjectAttributes { get; set; } = new();
    public Dictionary<string, AttributeValue> ResourceAttributes { get; set; } = new();
    public Dictionary<string, AttributeValue> ActionAttributes { get; set; } = new();
    public Dictionary<string, AttributeValue> EnvironmentAttributes { get; set; } = new();
}

public class AuthorizationResponse
{
    public Decision Decision { get; set; }
    public List<Obligation> Obligations { get; set; } = new();
    public List<string> Reasons { get; set; } = new();
    public string PolicyId { get; set; }
    public string RuleId { get; set; }
}

public enum Decision
{
    Permit,
    Deny,
    Indeterminate,
    NotApplicable
}
```

### 2. Policy Decision Point (PDP) Implementation

```csharp
public interface IPolicyDecisionPoint
{
    Task<AuthorizationResponse> EvaluateAsync(AuthorizationRequest request);
    Task<List<Policy>> GetApplicablePoliciesAsync(AuthorizationRequest request);
    Task<bool> ValidatePolicyAsync(Policy policy);
}

public class PolicyDecisionPoint : IPolicyDecisionPoint
{
    private readonly IPolicyRepository _policyRepository;
    private readonly IPolicyEvaluator _policyEvaluator;
    private readonly ILogger<PolicyDecisionPoint> _logger;
    private readonly IMemoryCache _cache;
    
    public PolicyDecisionPoint(
        IPolicyRepository policyRepository,
        IPolicyEvaluator policyEvaluator,
        ILogger<PolicyDecisionPoint> logger,
        IMemoryCache cache)
    {
        _policyRepository = policyRepository;
        _policyEvaluator = policyEvaluator;
        _logger = logger;
        _cache = cache;
    }
    
    public async Task<AuthorizationResponse> EvaluateAsync(AuthorizationRequest request)
    {
        try
        {
            var cacheKey = GenerateCacheKey(request);
            
            if (_cache.TryGetValue(cacheKey, out AuthorizationResponse cachedResponse))
            {
                _logger.LogDebug("Returning cached authorization decision");
                return cachedResponse;
            }
            
            var applicablePolicies = await GetApplicablePoliciesAsync(request);
            
            if (!applicablePolicies.Any())
            {
                _logger.LogInformation("No applicable policies found for request");
                return new AuthorizationResponse
                {
                    Decision = Decision.NotApplicable,
                    Reasons = new List<string> { "No applicable policies found" }
                };
            }
            
            var response = await EvaluatePoliciesAsync(applicablePolicies, request);
            
            // Cache the response for a short time
            _cache.Set(cacheKey, response, TimeSpan.FromMinutes(5));
            
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error evaluating authorization request");
            return new AuthorizationResponse
            {
                Decision = Decision.Indeterminate,
                Reasons = new List<string> { "Policy evaluation error" }
            };
        }
    }
    
    public async Task<List<Policy>> GetApplicablePoliciesAsync(AuthorizationRequest request)
    {
        var allPolicies = await _policyRepository.GetActivePoliciesAsync();
        var applicablePolicies = new List<Policy>();
        
        foreach (var policy in allPolicies)
        {
            if (await IsPolicyApplicableAsync(policy, request))
            {
                applicablePolicies.Add(policy);
            }
        }
        
        return applicablePolicies.OrderBy(p => p.Priority).ToList();
    }
    
    private async Task<bool> IsPolicyApplicableAsync(Policy policy, AuthorizationRequest request)
    {
        if (string.IsNullOrEmpty(policy.Target))
            return true; // Policy applies to all requests
        
        return await _policyEvaluator.EvaluateExpressionAsync(policy.Target, request);
    }
    
    private async Task<AuthorizationResponse> EvaluatePoliciesAsync(
        List<Policy> policies, 
        AuthorizationRequest request)
    {
        var obligations = new List<Obligation>();
        var reasons = new List<string>();
        
        // Policy combining algorithm: First applicable policy wins
        foreach (var policy in policies)
        {
            var policyResult = await EvaluatePolicyAsync(policy, request);
            
            if (policyResult.Decision == Decision.Permit || policyResult.Decision == Decision.Deny)
            {
                obligations.AddRange(policyResult.Obligations);
                reasons.AddRange(policyResult.Reasons);
                reasons.Add($"Decision from policy: {policy.Name}");
                
                return new AuthorizationResponse
                {
                    Decision = policyResult.Decision,
                    Obligations = obligations,
                    Reasons = reasons,
                    PolicyId = policy.Id.ToString(),
                    RuleId = policyResult.RuleId
                };
            }
        }
        
        // No policy provided a definitive decision
        return new AuthorizationResponse
        {
            Decision = Decision.NotApplicable,
            Reasons = new List<string> { "No policy provided a definitive decision" }
        };
    }
    
    private async Task<AuthorizationResponse> EvaluatePolicyAsync(Policy policy, AuthorizationRequest request)
    {
        var obligations = new List<Obligation>();
        var reasons = new List<string>();
        
        foreach (var rule in policy.Rules.OrderBy(r => r.Order))
        {
            var ruleResult = await _policyEvaluator.EvaluateExpressionAsync(rule.Condition, request);
            
            if (ruleResult)
            {
                obligations.AddRange(rule.Obligations);
                reasons.Add($"Rule matched: {rule.Id}");
                
                return new AuthorizationResponse
                {
                    Decision = rule.Effect == Effect.Permit ? Decision.Permit : Decision.Deny,
                    Obligations = obligations,
                    Reasons = reasons,
                    RuleId = rule.Id.ToString()
                };
            }
        }
        
        return new AuthorizationResponse
        {
            Decision = Decision.NotApplicable,
            Reasons = new List<string> { "No rules matched in policy" }
        };
    }
    
    public async Task<bool> ValidatePolicyAsync(Policy policy)
    {
        try
        {
            // Validate policy target expression
            if (!string.IsNullOrEmpty(policy.Target))
            {
                await _policyEvaluator.ValidateExpressionAsync(policy.Target);
            }
            
            // Validate rule conditions
            foreach (var rule in policy.Rules)
            {
                await _policyEvaluator.ValidateExpressionAsync(rule.Condition);
            }
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Policy validation failed for policy {PolicyId}", policy.Id);
            return false;
        }
    }
    
    private string GenerateCacheKey(AuthorizationRequest request)
    {
        // Create a hash of the request attributes for caching
        var keyData = string.Join("|",
            request.SubjectAttributes.Select(kv => $"{kv.Key}:{kv.Value.Value}").Concat(
            request.ResourceAttributes.Select(kv => $"{kv.Key}:{kv.Value.Value}")).Concat(
            request.ActionAttributes.Select(kv => $"{kv.Key}:{kv.Value.Value}")).Concat(
            request.EnvironmentAttributes.Select(kv => $"{kv.Key}:{kv.Value.Value}")));
        
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyData));
        return Convert.ToBase64String(hash);
    }
}
```

### 3. Policy Evaluator Implementation

```csharp
public interface IPolicyEvaluator
{
    Task<bool> EvaluateExpressionAsync(string expression, AuthorizationRequest request);
    Task ValidateExpressionAsync(string expression);
}

public class JsonPolicyEvaluator : IPolicyEvaluator
{
    private readonly ILogger<JsonPolicyEvaluator> _logger;
    
    public JsonPolicyEvaluator(ILogger<JsonPolicyEvaluator> logger)
    {
        _logger = logger;
    }
    
    public async Task<bool> EvaluateExpressionAsync(string expression, AuthorizationRequest request)
    {
        try
        {
            var condition = JsonSerializer.Deserialize<PolicyCondition>(expression);
            return await EvaluateConditionAsync(condition, request);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error evaluating expression: {Expression}", expression);
            return false;
        }
    }
    
    private async Task<bool> EvaluateConditionAsync(PolicyCondition condition, AuthorizationRequest request)
    {
        switch (condition.Operator?.ToLower())
        {
            case "and":
                return await EvaluateAndAsync(condition.Conditions, request);
            case "or":
                return await EvaluateOrAsync(condition.Conditions, request);
            case "not":
                return !await EvaluateConditionAsync(condition.Conditions?.FirstOrDefault(), request);
            case "equals":
                return EvaluateEquals(condition, request);
            case "notequals":
                return !EvaluateEquals(condition, request);
            case "contains":
                return EvaluateContains(condition, request);
            case "greaterthan":
                return EvaluateGreaterThan(condition, request);
            case "lessthan":
                return EvaluateLessThan(condition, request);
            case "in":
                return EvaluateIn(condition, request);
            case "regex":
                return EvaluateRegex(condition, request);
            case "timerange":
                return EvaluateTimeRange(condition, request);
            default:
                _logger.LogWarning("Unknown operator: {Operator}", condition.Operator);
                return false;
        }
    }
    
    private async Task<bool> EvaluateAndAsync(List<PolicyCondition> conditions, AuthorizationRequest request)
    {
        if (conditions == null || !conditions.Any())
            return true;
        
        foreach (var condition in conditions)
        {
            if (!await EvaluateConditionAsync(condition, request))
                return false;
        }
        
        return true;
    }
    
    private async Task<bool> EvaluateOrAsync(List<PolicyCondition> conditions, AuthorizationRequest request)
    {
        if (conditions == null || !conditions.Any())
            return false;
        
        foreach (var condition in conditions)
        {
            if (await EvaluateConditionAsync(condition, request))
                return true;
        }
        
        return false;
    }
    
    private bool EvaluateEquals(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        return attributeValue.Value?.ToString() == condition.Value?.ToString();
    }
    
    private bool EvaluateContains(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        var value = attributeValue.Value?.ToString();
        var searchValue = condition.Value?.ToString();
        
        return !string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(searchValue) && 
               value.Contains(searchValue, StringComparison.OrdinalIgnoreCase);
    }
    
    private bool EvaluateGreaterThan(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        if (attributeValue.Type == AttributeType.Integer)
        {
            return Convert.ToInt32(attributeValue.Value) > Convert.ToInt32(condition.Value);
        }
        
        if (attributeValue.Type == AttributeType.DateTime)
        {
            return Convert.ToDateTime(attributeValue.Value) > Convert.ToDateTime(condition.Value);
        }
        
        return false;
    }
    
    private bool EvaluateLessThan(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        if (attributeValue.Type == AttributeType.Integer)
        {
            return Convert.ToInt32(attributeValue.Value) < Convert.ToInt32(condition.Value);
        }
        
        if (attributeValue.Type == AttributeType.DateTime)
        {
            return Convert.ToDateTime(attributeValue.Value) < Convert.ToDateTime(condition.Value);
        }
        
        return false;
    }
    
    private bool EvaluateIn(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        var values = condition.Values ?? new List<object>();
        return values.Contains(attributeValue.Value);
    }
    
    private bool EvaluateRegex(PolicyCondition condition, AuthorizationRequest request)
    {
        var attributeValue = GetAttributeValue(condition.AttributeName, request);
        if (attributeValue == null) return false;
        
        var value = attributeValue.Value?.ToString();
        var pattern = condition.Value?.ToString();
        
        if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(pattern))
            return false;
        
        try
        {
            return Regex.IsMatch(value, pattern);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error evaluating regex pattern: {Pattern}", pattern);
            return false;
        }
    }
    
    private bool EvaluateTimeRange(PolicyCondition condition, AuthorizationRequest request)
    {
        var currentTime = DateTime.UtcNow;
        
        if (condition.StartTime.HasValue && currentTime < condition.StartTime.Value)
            return false;
        
        if (condition.EndTime.HasValue && currentTime > condition.EndTime.Value)
            return false;
        
        return true;
    }
    
    private AttributeValue GetAttributeValue(string attributeName, AuthorizationRequest request)
    {
        // Check all attribute categories
        if (request.SubjectAttributes.TryGetValue(attributeName, out var subjectAttr))
            return subjectAttr;
        
        if (request.ResourceAttributes.TryGetValue(attributeName, out var resourceAttr))
            return resourceAttr;
        
        if (request.ActionAttributes.TryGetValue(attributeName, out var actionAttr))
            return actionAttr;
        
        if (request.EnvironmentAttributes.TryGetValue(attributeName, out var envAttr))
            return envAttr;
        
        return null;
    }
    
    public async Task ValidateExpressionAsync(string expression)
    {
        try
        {
            var condition = JsonSerializer.Deserialize<PolicyCondition>(expression);
            ValidateCondition(condition);
            await Task.CompletedTask;
        }
        catch (JsonException ex)
        {
            throw new ArgumentException("Invalid JSON expression", ex);
        }
    }
    
    private void ValidateCondition(PolicyCondition condition)
    {
        if (condition == null)
            throw new ArgumentException("Condition cannot be null");
        
        var validOperators = new[] { "and", "or", "not", "equals", "notequals", "contains", 
                                   "greaterthan", "lessthan", "in", "regex", "timerange" };
        
        if (!validOperators.Contains(condition.Operator?.ToLower()))
            throw new ArgumentException($"Invalid operator: {condition.Operator}");
        
        if (condition.Conditions != null)
        {
            foreach (var subCondition in condition.Conditions)
            {
                ValidateCondition(subCondition);
            }
        }
    }
}

public class PolicyCondition
{
    public string Operator { get; set; }
    public string AttributeName { get; set; }
    public object Value { get; set; }
    public List<object> Values { get; set; }
    public List<PolicyCondition> Conditions { get; set; }
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }
}
```

### 4. Policy Information Point (PIP) Implementation

```csharp
public interface IPolicyInformationPoint
{
    Task<Dictionary<string, AttributeValue>> GetSubjectAttributesAsync(string subjectId);
    Task<Dictionary<string, AttributeValue>> GetResourceAttributesAsync(string resourceId);
    Task<Dictionary<string, AttributeValue>> GetEnvironmentAttributesAsync(HttpContext context);
    Task<AttributeValue> GetAttributeAsync(string attributeName, string entityId, AttributeCategory category);
}

public class PolicyInformationPoint : IPolicyInformationPoint
{
    private readonly IUserService _userService;
    private readonly IResourceService _resourceService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IMemoryCache _cache;
    private readonly ILogger<PolicyInformationPoint> _logger;
    
    public PolicyInformationPoint(
        IUserService userService,
        IResourceService resourceService,
        IHttpContextAccessor httpContextAccessor,
        IMemoryCache cache,
        ILogger<PolicyInformationPoint> logger)
    {
        _userService = userService;
        _resourceService = resourceService;
        _httpContextAccessor = httpContextAccessor;
        _cache = cache;
        _logger = logger;
    }
    
    public async Task<Dictionary<string, AttributeValue>> GetSubjectAttributesAsync(string subjectId)
    {
        var cacheKey = $"subject_attributes_{subjectId}";
        
        if (_cache.TryGetValue(cacheKey, out Dictionary<string, AttributeValue> cachedAttributes))
            return cachedAttributes;
        
        var attributes = new Dictionary<string, AttributeValue>();
        
        try
        {
            var user = await _userService.GetUserByIdAsync(subjectId);
            if (user == null) return attributes;
            
            // Basic user attributes
            attributes["user.id"] = new AttributeValue { Name = "user.id", Value = user.Id, Type = AttributeType.String, Category = AttributeCategory.Subject };
            attributes["user.email"] = new AttributeValue { Name = "user.email", Value = user.Email, Type = AttributeType.String, Category = AttributeCategory.Subject };
            attributes["user.department"] = new AttributeValue { Name = "user.department", Value = user.Department, Type = AttributeType.String, Category = AttributeCategory.Subject };
            attributes["user.role"] = new AttributeValue { Name = "user.role", Value = user.Role, Type = AttributeType.String, Category = AttributeCategory.Subject };
            attributes["user.clearance_level"] = new AttributeValue { Name = "user.clearance_level", Value = user.ClearanceLevel, Type = AttributeType.String, Category = AttributeCategory.Subject };
            attributes["user.hire_date"] = new AttributeValue { Name = "user.hire_date", Value = user.HireDate, Type = AttributeType.DateTime, Category = AttributeCategory.Subject };
            
            // Group memberships
            var groups = await _userService.GetUserGroupsAsync(subjectId);
            attributes["user.groups"] = new AttributeValue { Name = "user.groups", Value = groups, Type = AttributeType.Collection, Category = AttributeCategory.Subject };
            
            // Dynamic attributes
            var age = CalculateAge(user.DateOfBirth);
            attributes["user.age"] = new AttributeValue { Name = "user.age", Value = age, Type = AttributeType.Integer, Category = AttributeCategory.Subject };
            
            var tenure = CalculateTenure(user.HireDate);
            attributes["user.tenure_years"] = new AttributeValue { Name = "user.tenure_years", Value = tenure, Type = AttributeType.Integer, Category = AttributeCategory.Subject };
            
            // Performance-based attributes
            var performanceRating = await _userService.GetLatestPerformanceRatingAsync(subjectId);
            attributes["user.performance_rating"] = new AttributeValue { Name = "user.performance_rating", Value = performanceRating, Type = AttributeType.String, Category = AttributeCategory.Subject };
            
            _cache.Set(cacheKey, attributes, TimeSpan.FromMinutes(30));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving subject attributes for user {UserId}", subjectId);
        }
        
        return attributes;
    }
    
    public async Task<Dictionary<string, AttributeValue>> GetResourceAttributesAsync(string resourceId)
    {
        var cacheKey = $"resource_attributes_{resourceId}";
        
        if (_cache.TryGetValue(cacheKey, out Dictionary<string, AttributeValue> cachedAttributes))
            return cachedAttributes;
        
        var attributes = new Dictionary<string, AttributeValue>();
        
        try
        {
            var resource = await _resourceService.GetResourceAsync(resourceId);
            if (resource == null) return attributes;
            
            attributes["resource.id"] = new AttributeValue { Name = "resource.id", Value = resource.Id, Type = AttributeType.String, Category = AttributeCategory.Resource };
            attributes["resource.type"] = new AttributeValue { Name = "resource.type", Value = resource.Type, Type = AttributeType.String, Category = AttributeCategory.Resource };
            attributes["resource.classification"] = new AttributeValue { Name = "resource.classification", Value = resource.Classification, Type = AttributeType.String, Category = AttributeCategory.Resource };
            attributes["resource.owner_id"] = new AttributeValue { Name = "resource.owner_id", Value = resource.OwnerId, Type = AttributeType.String, Category = AttributeCategory.Resource };
            attributes["resource.department"] = new AttributeValue { Name = "resource.department", Value = resource.Department, Type = AttributeType.String, Category = AttributeCategory.Resource };
            attributes["resource.created_date"] = new AttributeValue { Name = "resource.created_date", Value = resource.CreatedAt, Type = AttributeType.DateTime, Category = AttributeCategory.Resource };
            attributes["resource.size"] = new AttributeValue { Name = "resource.size", Value = resource.Size, Type = AttributeType.Integer, Category = AttributeCategory.Resource };
            
            // Dynamic attributes
            var age = DateTime.UtcNow - resource.CreatedAt;
            attributes["resource.age_days"] = new AttributeValue { Name = "resource.age_days", Value = (int)age.TotalDays, Type = AttributeType.Integer, Category = AttributeCategory.Resource };
            
            var tags = await _resourceService.GetResourceTagsAsync(resourceId);
            attributes["resource.tags"] = new AttributeValue { Name = "resource.tags", Value = tags, Type = AttributeType.Collection, Category = AttributeCategory.Resource };
            
            _cache.Set(cacheKey, attributes, TimeSpan.FromMinutes(15));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving resource attributes for resource {ResourceId}", resourceId);
        }
        
        return attributes;
    }
    
    public async Task<Dictionary<string, AttributeValue>> GetEnvironmentAttributesAsync(HttpContext context)
    {
        var attributes = new Dictionary<string, AttributeValue>();
        
        try
        {
            // Time-based attributes
            var now = DateTime.UtcNow;
            attributes["environment.current_time"] = new AttributeValue { Name = "environment.current_time", Value = now, Type = AttributeType.DateTime, Category = AttributeCategory.Environment };
            attributes["environment.day_of_week"] = new AttributeValue { Name = "environment.day_of_week", Value = now.DayOfWeek.ToString(), Type = AttributeType.String, Category = AttributeCategory.Environment };
            attributes["environment.hour"] = new AttributeValue { Name = "environment.hour", Value = now.Hour, Type = AttributeType.Integer, Category = AttributeCategory.Environment };
            
            // Network attributes
            var ipAddress = GetClientIpAddress(context);
            attributes["environment.ip_address"] = new AttributeValue { Name = "environment.ip_address", Value = ipAddress, Type = AttributeType.String, Category = AttributeCategory.Environment };
            
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            attributes["environment.user_agent"] = new AttributeValue { Name = "environment.user_agent", Value = userAgent, Type = AttributeType.String, Category = AttributeCategory.Environment };
            
            // Device attributes
            var isMobile = IsMobileDevice(userAgent);
            attributes["environment.is_mobile"] = new AttributeValue { Name = "environment.is_mobile", Value = isMobile, Type = AttributeType.Boolean, Category = AttributeCategory.Environment };
            
            // Security attributes
            var isSecureConnection = context.Request.IsHttps;
            attributes["environment.is_https"] = new AttributeValue { Name = "environment.is_https", Value = isSecureConnection, Type = AttributeType.Boolean, Category = AttributeCategory.Environment };
            
            // Location attributes (would typically come from IP geolocation service)
            var country = await GetCountryFromIpAsync(ipAddress);
            attributes["environment.country"] = new AttributeValue { Name = "environment.country", Value = country, Type = AttributeType.String, Category = AttributeCategory.Environment };
            
            // Risk attributes
            var riskScore = await CalculateRiskScoreAsync(context);
            attributes["environment.risk_score"] = new AttributeValue { Name = "environment.risk_score", Value = riskScore, Type = AttributeType.Integer, Category = AttributeCategory.Environment };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving environment attributes");
        }
        
        return attributes;
    }
    
    public async Task<AttributeValue> GetAttributeAsync(string attributeName, string entityId, AttributeCategory category)
    {
        return category switch
        {
            AttributeCategory.Subject => (await GetSubjectAttributesAsync(entityId)).GetValueOrDefault(attributeName),
            AttributeCategory.Resource => (await GetResourceAttributesAsync(entityId)).GetValueOrDefault(attributeName),
            AttributeCategory.Environment => (await GetEnvironmentAttributesAsync(_httpContextAccessor.HttpContext)).GetValueOrDefault(attributeName),
            _ => null
        };
    }
    
    private int CalculateAge(DateTime dateOfBirth)
    {
        var age = DateTime.Today.Year - dateOfBirth.Year;
        if (dateOfBirth.Date > DateTime.Today.AddYears(-age))
            age--;
        return age;
    }
    
    private int CalculateTenure(DateTime hireDate)
    {
        return DateTime.Today.Year - hireDate.Year;
    }
    
    private string GetClientIpAddress(HttpContext context)
    {
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
            return forwardedFor.Split(',')[0].Trim();
        
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
    
    private bool IsMobileDevice(string userAgent)
    {
        var mobileKeywords = new[] { "Mobile", "Android", "iPhone", "iPad", "Windows Phone" };
        return mobileKeywords.Any(keyword => userAgent.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }
    
    private async Task<string> GetCountryFromIpAsync(string ipAddress)
    {
        // Implementation would use IP geolocation service
        return await Task.FromResult("US"); // Simplified
    }
    
    private async Task<int> CalculateRiskScoreAsync(HttpContext context)
    {
        // Implementation would calculate risk based on various factors
        // - Failed login attempts
        // - Unusual location
        // - Time of access
        // - Device trust level
        return await Task.FromResult(50); // Simplified
    }
}
```

### 5. ABAC Authorization Handler

```csharp
public class AbacAuthorizationRequirement : IAuthorizationRequirement
{
    public string PolicyName { get; }
    
    public AbacAuthorizationRequirement(string policyName)
    {
        PolicyName = policyName;
    }
}

public class AbacAuthorizationHandler : AuthorizationHandler<AbacAuthorizationRequirement, object>
{
    private readonly IPolicyDecisionPoint _pdp;
    private readonly IPolicyInformationPoint _pip;
    private readonly IObligationHandler _obligationHandler;
    private readonly ILogger<AbacAuthorizationHandler> _logger;
    
    public AbacAuthorizationHandler(
        IPolicyDecisionPoint pdp,
        IPolicyInformationPoint pip,
        IObligationHandler obligationHandler,
        ILogger<AbacAuthorizationHandler> logger)
    {
        _pdp = pdp;
        _pip = pip;
        _obligationHandler = obligationHandler;
        _logger = logger;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AbacAuthorizationRequirement requirement,
        object resource)
    {
        try
        {
            var request = await BuildAuthorizationRequestAsync(context, resource);
            var response = await _pdp.EvaluateAsync(request);
            
            _logger.LogInformation("ABAC decision: {Decision} for policy {Policy}", 
                response.Decision, requirement.PolicyName);
            
            if (response.Decision == Decision.Permit)
            {
                context.Succeed(requirement);
                
                // Handle obligations
                if (response.Obligations.Any())
                {
                    await _obligationHandler.HandleObligationsAsync(response.Obligations, context);
                }
            }
            else if (response.Decision == Decision.Deny)
            {
                context.Fail();
                _logger.LogWarning("Access denied. Reasons: {Reasons}", 
                    string.Join(", ", response.Reasons));
            }
            // For Indeterminate or NotApplicable, we don't succeed or fail
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in ABAC authorization handler");
            context.Fail();
        }
    }
    
    private async Task<AuthorizationRequest> BuildAuthorizationRequestAsync(
        AuthorizationHandlerContext context, 
        object resource)
    {
        var request = new AuthorizationRequest();
        
        // Subject attributes
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId))
        {
            request.SubjectAttributes = await _pip.GetSubjectAttributesAsync(userId);
        }
        
        // Resource attributes
        if (resource is IResource resourceObj)
        {
            request.ResourceAttributes = await _pip.GetResourceAttributesAsync(resourceObj.Id.ToString());
        }
        
        // Action attributes (inferred from context)
        var httpContext = context.Resource as HttpContext;
        if (httpContext != null)
        {
            var method = httpContext.Request.Method;
            request.ActionAttributes["action.method"] = new AttributeValue 
            { 
                Name = "action.method", 
                Value = method, 
                Type = AttributeType.String, 
                Category = AttributeCategory.Action 
            };
        }
        
        // Environment attributes
        if (httpContext != null)
        {
            request.EnvironmentAttributes = await _pip.GetEnvironmentAttributesAsync(httpContext);
        }
        
        return request;
    }
}
```

## Security Best Practices

### 1. Policy Security
```csharp
public class PolicySecurityValidator
{
    public bool ValidatePolicy(Policy policy)
    {
        // Check for policy conflicts
        if (HasConflictingRules(policy))
            return false;
        
        // Validate attribute references
        if (!ValidateAttributeReferences(policy))
            return false;
        
        // Check for infinite loops
        if (HasCircularReferences(policy))
            return false;
        
        return true;
    }
    
    private bool HasConflictingRules(Policy policy)
    {
        // Implementation to detect conflicting permit/deny rules
        return false;
    }
    
    private bool ValidateAttributeReferences(Policy policy)
    {
        // Implementation to validate all referenced attributes exist
        return true;
    }
    
    private bool HasCircularReferences(Policy policy)
    {
        // Implementation to detect circular policy references
        return false;
    }
}
```

### 2. Performance Optimization
```csharp
public class OptimizedPolicyDecisionPoint : IPolicyDecisionPoint
{
    private readonly IPolicyDecisionPoint _basePdp;
    private readonly IDistributedCache _cache;
    
    public async Task<AuthorizationResponse> EvaluateAsync(AuthorizationRequest request)
    {
        // Use distributed cache for high-performance scenarios
        var cacheKey = GenerateDistributedCacheKey(request);
        var cachedResponse = await _cache.GetStringAsync(cacheKey);
        
        if (cachedResponse != null)
        {
            return JsonSerializer.Deserialize<AuthorizationResponse>(cachedResponse);
        }
        
        var response = await _basePdp.EvaluateAsync(request);
        
        await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(response), 
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)
            });
        
        return response;
    }
    
    // Other methods delegate to base implementation
    public Task<List<Policy>> GetApplicablePoliciesAsync(AuthorizationRequest request) => _basePdp.GetApplicablePoliciesAsync(request);
    public Task<bool> ValidatePolicyAsync(Policy policy) => _basePdp.ValidatePolicyAsync(policy);
}
```

## Testing Strategies

### 1. Policy Testing
```csharp
[TestFixture]
public class AbacPolicyTests
{
    private PolicyDecisionPoint _pdp;
    private Mock<IPolicyRepository> _mockRepo;
    private Mock<IPolicyEvaluator> _mockEvaluator;
    
    [SetUp]
    public void Setup()
    {
        _mockRepo = new Mock<IPolicyRepository>();
        _mockEvaluator = new Mock<IPolicyEvaluator>();
        _pdp = new PolicyDecisionPoint(_mockRepo.Object, _mockEvaluator.Object, null, null);
    }
    
    [Test]
    public async Task EvaluateAsync_WithPermitPolicy_ShouldReturnPermit()
    {
        // Arrange
        var request = new AuthorizationRequest();
        var policy = CreateTestPolicy("TestPolicy", Effect.Permit);
        
        _mockRepo.Setup(r => r.GetActivePoliciesAsync()).ReturnsAsync(new List<Policy> { policy });
        _mockEvaluator.Setup(e => e.EvaluateExpressionAsync(It.IsAny<string>(), It.IsAny<AuthorizationRequest>()))
                     .ReturnsAsync(true);
        
        // Act
        var response = await _pdp.EvaluateAsync(request);
        
        // Assert
        Assert.AreEqual(Decision.Permit, response.Decision);
    }
}
```

---
**Next**: Continue with the remaining authentication and authorization notes