# Implementation Patterns

## Overview
This document outlines comprehensive implementation patterns for authentication and authorization in .NET applications. These patterns provide reusable architectural solutions, design patterns, and implementation strategies that have proven effective in real-world applications.

## Architectural Patterns

### 1. Clean Architecture for Auth

```csharp
// Domain Layer - Core entities and business rules
namespace AuthDomain.Entities
{
    public class User : AggregateRoot
    {
        public UserId Id { get; private set; }
        public Email Email { get; private set; }
        public PasswordHash PasswordHash { get; private set; }
        public UserStatus Status { get; private set; }
        public DateTime CreatedAt { get; private set; }
        private readonly List<UserRole> _roles = new();
        private readonly List<DomainEvent> _domainEvents = new();
        
        public IReadOnlyCollection<UserRole> Roles => _roles.AsReadOnly();
        public IReadOnlyCollection<DomainEvent> DomainEvents => _domainEvents.AsReadOnly();
        
        private User() { } // EF Constructor
        
        public User(Email email, PasswordHash passwordHash)
        {
            Id = new UserId(Guid.NewGuid());
            Email = email ?? throw new ArgumentNullException(nameof(email));
            PasswordHash = passwordHash ?? throw new ArgumentNullException(nameof(passwordHash));
            Status = UserStatus.Active;
            CreatedAt = DateTime.UtcNow;
            
            _domainEvents.Add(new UserCreatedEvent(Id, Email));
        }
        
        public void ChangePassword(PasswordHash newPasswordHash)
        {
            if (Status != UserStatus.Active)
                throw new DomainException("Cannot change password for inactive user");
            
            PasswordHash = newPasswordHash;
            _domainEvents.Add(new PasswordChangedEvent(Id));
        }
        
        public void AssignRole(Role role)
        {
            if (_roles.Any(r => r.RoleId == role.Id))
                return; // Already has role
            
            _roles.Add(new UserRole(Id, role.Id));
            _domainEvents.Add(new RoleAssignedEvent(Id, role.Id));
        }
        
        public void RemoveRole(RoleId roleId)
        {
            var userRole = _roles.FirstOrDefault(r => r.RoleId == roleId);
            if (userRole != null)
            {
                _roles.Remove(userRole);
                _domainEvents.Add(new RoleRemovedEvent(Id, roleId));
            }
        }
        
        public void Suspend(string reason)
        {
            Status = UserStatus.Suspended;
            _domainEvents.Add(new UserSuspendedEvent(Id, reason));
        }
        
        public bool HasPermission(Permission permission)
        {
            return _roles.Any(r => r.Role.HasPermission(permission));
        }
        
        public void ClearDomainEvents()
        {
            _domainEvents.Clear();
        }
    }
    
    // Value Objects
    public class Email : ValueObject
    {
        public string Value { get; }
        
        public Email(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Email cannot be empty");
            
            if (!IsValidEmail(value))
                throw new ArgumentException("Invalid email format");
            
            Value = value.ToLowerInvariant();
        }
        
        private static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }
        
        protected override IEnumerable<object> GetEqualityComponents()
        {
            yield return Value;
        }
    }
    
    public class PasswordHash : ValueObject
    {
        public string Value { get; }
        public string Salt { get; }
        public string Algorithm { get; }
        
        public PasswordHash(string value, string salt, string algorithm = "Argon2id")
        {
            Value = value ?? throw new ArgumentNullException(nameof(value));
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        }
        
        protected override IEnumerable<object> GetEqualityComponents()
        {
            yield return Value;
            yield return Salt;
            yield return Algorithm;
        }
    }
}

// Application Layer - Use cases and application services
namespace AuthApplication.UseCases
{
    public class AuthenticateUserUseCase : IAuthenticateUserUseCase
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly IEventDispatcher _eventDispatcher;
        private readonly ILogger<AuthenticateUserUseCase> _logger;
        
        public AuthenticateUserUseCase(
            IUserRepository userRepository,
            IPasswordService passwordService,
            ITokenService tokenService,
            IEventDispatcher eventDispatcher,
            ILogger<AuthenticateUserUseCase> logger)
        {
            _userRepository = userRepository;
            _passwordService = passwordService;
            _tokenService = tokenService;
            _eventDispatcher = eventDispatcher;
            _logger = logger;
        }
        
        public async Task<AuthenticationResult> ExecuteAsync(AuthenticateUserCommand command)
        {
            try
            {
                // Find user
                var user = await _userRepository.FindByEmailAsync(new Email(command.Email));
                if (user == null)
                {
                    _logger.LogWarning("Authentication attempt for non-existent user: {Email}", command.Email);
                    return AuthenticationResult.Failed("Invalid credentials");
                }
                
                // Verify password
                if (!_passwordService.VerifyPassword(command.Password, user.PasswordHash))
                {
                    _logger.LogWarning("Authentication failed for user: {UserId}", user.Id);
                    return AuthenticationResult.Failed("Invalid credentials");
                }
                
                // Check user status
                if (user.Status != UserStatus.Active)
                {
                    _logger.LogWarning("Authentication attempt for inactive user: {UserId}", user.Id);
                    return AuthenticationResult.Failed("Account is disabled");
                }
                
                // Generate token
                var tokenRequest = new TokenRequest
                {
                    UserId = user.Id.Value.ToString(),
                    Email = user.Email.Value,
                    Roles = user.Roles.Select(r => r.Role.Name).ToList()
                };
                
                var token = await _tokenService.GenerateTokenAsync(tokenRequest);
                
                // Dispatch events
                foreach (var domainEvent in user.DomainEvents)
                {
                    await _eventDispatcher.DispatchAsync(domainEvent);
                }
                user.ClearDomainEvents();
                
                _logger.LogInformation("User authenticated successfully: {UserId}", user.Id);
                
                return AuthenticationResult.Success(token, user.Id.Value.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error authenticating user: {Email}", command.Email);
                return AuthenticationResult.Failed("Authentication error");
            }
        }
    }
    
    public class CreateUserUseCase : ICreateUserUseCase
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordService _passwordService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventDispatcher _eventDispatcher;
        private readonly ILogger<CreateUserUseCase> _logger;
        
        public async Task<CreateUserResult> ExecuteAsync(CreateUserCommand command)
        {
            try
            {
                var email = new Email(command.Email);
                
                // Check if user already exists
                var existingUser = await _userRepository.FindByEmailAsync(email);
                if (existingUser != null)
                {
                    return CreateUserResult.Failed("User already exists");
                }
                
                // Hash password
                var passwordHash = _passwordService.HashPassword(command.Password);
                
                // Create user
                var user = new User(email, passwordHash);
                
                // Add to repository
                await _userRepository.AddAsync(user);
                
                // Save changes
                await _unitOfWork.SaveChangesAsync();
                
                // Dispatch events
                foreach (var domainEvent in user.DomainEvents)
                {
                    await _eventDispatcher.DispatchAsync(domainEvent);
                }
                user.ClearDomainEvents();
                
                _logger.LogInformation("User created successfully: {UserId}", user.Id);
                
                return CreateUserResult.Success(user.Id.Value.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user: {Email}", command.Email);
                return CreateUserResult.Failed("User creation failed");
            }
        }
    }
}

// Infrastructure Layer - External concerns
namespace AuthInfrastructure.Persistence
{
    public class UserRepository : IUserRepository
    {
        private readonly AuthDbContext _context;
        
        public UserRepository(AuthDbContext context)
        {
            _context = context;
        }
        
        public async Task<User> FindByEmailAsync(Email email)
        {
            return await _context.Users
                .Include(u => u.Roles)
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Email.Value == email.Value);
        }
        
        public async Task<User> FindByIdAsync(UserId id)
        {
            return await _context.Users
                .Include(u => u.Roles)
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Id == id);
        }
        
        public async Task AddAsync(User user)
        {
            await _context.Users.AddAsync(user);
        }
        
        public void Update(User user)
        {
            _context.Users.Update(user);
        }
        
        public void Remove(User user)
        {
            _context.Users.Remove(user);
        }
    }
}
```

### 2. CQRS Pattern for Auth Operations

```csharp
// Command side - Write operations
namespace AuthApplication.Commands
{
    public class RegisterUserCommand : ICommand<RegisterUserResult>
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
    
    public class RegisterUserCommandHandler : ICommandHandler<RegisterUserCommand, RegisterUserResult>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordService _passwordService;
        private readonly IEmailService _emailService;
        private readonly IEventBus _eventBus;
        private readonly ILogger<RegisterUserCommandHandler> _logger;
        
        public async Task<RegisterUserResult> Handle(RegisterUserCommand command, CancellationToken cancellationToken)
        {
            // Validation
            var validationResult = await ValidateCommand(command);
            if (!validationResult.IsValid)
            {
                return RegisterUserResult.Failed(validationResult.Errors);
            }
            
            // Create user
            var email = new Email(command.Email);
            var passwordHash = _passwordService.HashPassword(command.Password);
            var user = new User(email, passwordHash);
            
            // Save user
            await _userRepository.AddAsync(user);
            await _userRepository.UnitOfWork.SaveChangesAsync(cancellationToken);
            
            // Publish events
            await _eventBus.PublishAsync(new UserRegisteredEvent
            {
                UserId = user.Id.Value,
                Email = user.Email.Value,
                FirstName = command.FirstName,
                LastName = command.LastName
            }, cancellationToken);
            
            _logger.LogInformation("User registered: {UserId}", user.Id);
            
            return RegisterUserResult.Success(user.Id.Value);
        }
        
        private async Task<ValidationResult> ValidateCommand(RegisterUserCommand command)
        {
            var result = new ValidationResult();
            
            // Email validation
            if (string.IsNullOrWhiteSpace(command.Email))
            {
                result.AddError("Email is required");
            }
            else if (await _userRepository.ExistsByEmailAsync(new Email(command.Email)))
            {
                result.AddError("Email is already registered");
            }
            
            // Password validation
            if (string.IsNullOrWhiteSpace(command.Password))
            {
                result.AddError("Password is required");
            }
            else if (!_passwordService.IsValidPassword(command.Password))
            {
                result.AddError("Password does not meet requirements");
            }
            
            return result;
        }
    }
}

// Query side - Read operations
namespace AuthApplication.Queries
{
    public class GetUserByIdQuery : IQuery<UserDto>
    {
        public Guid UserId { get; set; }
    }
    
    public class GetUserByIdQueryHandler : IQueryHandler<GetUserByIdQuery, UserDto>
    {
        private readonly IUserReadRepository _userReadRepository;
        private readonly IMemoryCache _cache;
        
        public GetUserByIdQueryHandler(IUserReadRepository userReadRepository, IMemoryCache cache)
        {
            _userReadRepository = userReadRepository;
            _cache = cache;
        }
        
        public async Task<UserDto> Handle(GetUserByIdQuery query, CancellationToken cancellationToken)
        {
            var cacheKey = $"user_{query.UserId}";
            
            if (_cache.TryGetValue(cacheKey, out UserDto cachedUser))
            {
                return cachedUser;
            }
            
            var user = await _userReadRepository.GetByIdAsync(query.UserId);
            
            if (user != null)
            {
                _cache.Set(cacheKey, user, TimeSpan.FromMinutes(15));
            }
            
            return user;
        }
    }
    
    public class GetUserPermissionsQuery : IQuery<List<string>>
    {
        public Guid UserId { get; set; }
        public string ResourceType { get; set; }
        public string ResourceId { get; set; }
    }
    
    public class GetUserPermissionsQueryHandler : IQueryHandler<GetUserPermissionsQuery, List<string>>
    {
        private readonly IPermissionReadRepository _permissionRepository;
        private readonly IDistributedCache _cache;
        
        public async Task<List<string>> Handle(GetUserPermissionsQuery query, CancellationToken cancellationToken)
        {
            var cacheKey = $"permissions_{query.UserId}_{query.ResourceType}_{query.ResourceId}";
            
            var cachedPermissions = await _cache.GetStringAsync(cacheKey, cancellationToken);
            if (!string.IsNullOrEmpty(cachedPermissions))
            {
                return JsonSerializer.Deserialize<List<string>>(cachedPermissions);
            }
            
            var permissions = await _permissionRepository.GetUserPermissionsAsync(
                query.UserId, query.ResourceType, query.ResourceId);
            
            await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(permissions),
                new DistributedCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromMinutes(30)
                }, cancellationToken);
            
            return permissions;
        }
    }
}

// Event handlers for cross-cutting concerns
namespace AuthApplication.EventHandlers
{
    public class UserRegisteredEventHandler : IEventHandler<UserRegisteredEvent>
    {
        private readonly IEmailService _emailService;
        private readonly ILogger<UserRegisteredEventHandler> _logger;
        
        public async Task Handle(UserRegisteredEvent @event, CancellationToken cancellationToken)
        {
            try
            {
                await _emailService.SendWelcomeEmailAsync(@event.Email, @event.FirstName);
                _logger.LogInformation("Welcome email sent to {Email}", @event.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send welcome email to {Email}", @event.Email);
                // Don't throw - email failure shouldn't fail user registration
            }
        }
    }
    
    public class PasswordChangedEventHandler : IEventHandler<PasswordChangedEvent>
    {
        private readonly ISessionService _sessionService;
        private readonly IEmailService _emailService;
        private readonly IUserReadRepository _userRepository;
        
        public async Task Handle(PasswordChangedEvent @event, CancellationToken cancellationToken)
        {
            // Invalidate all user sessions
            await _sessionService.InvalidateAllUserSessionsAsync(@event.UserId.ToString());
            
            // Send notification email
            var user = await _userRepository.GetByIdAsync(@event.UserId.Value);
            if (user != null)
            {
                await _emailService.SendPasswordChangedNotificationAsync(user.Email);
            }
        }
    }
}
```

### 3. Repository Pattern with Unit of Work

```csharp
// Repository interfaces
namespace AuthDomain.Repositories
{
    public interface IRepository<T> where T : AggregateRoot
    {
        IUnitOfWork UnitOfWork { get; }
    }
    
    public interface IUserRepository : IRepository<User>
    {
        Task<User> FindByIdAsync(UserId id);
        Task<User> FindByEmailAsync(Email email);
        Task<bool> ExistsByEmailAsync(Email email);
        Task AddAsync(User user);
        void Update(User user);
        void Remove(User user);
    }
    
    public interface IUnitOfWork : IDisposable
    {
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
        Task BeginTransactionAsync();
        Task CommitTransactionAsync();
        Task RollbackTransactionAsync();
    }
}

// Repository implementation
namespace AuthInfrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AuthDbContext _context;
        
        public UserRepository(AuthDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }
        
        public IUnitOfWork UnitOfWork => _context;
        
        public async Task<User> FindByIdAsync(UserId id)
        {
            return await _context.Users
                .Include(u => u.Roles)
                .ThenInclude(ur => ur.Role)
                .ThenInclude(r => r.Permissions)
                .FirstOrDefaultAsync(u => u.Id == id);
        }
        
        public async Task<User> FindByEmailAsync(Email email)
        {
            return await _context.Users
                .Include(u => u.Roles)
                .ThenInclude(ur => ur.Role)
                .ThenInclude(r => r.Permissions)
                .FirstOrDefaultAsync(u => u.Email.Value == email.Value);
        }
        
        public async Task<bool> ExistsByEmailAsync(Email email)
        {
            return await _context.Users
                .AnyAsync(u => u.Email.Value == email.Value);
        }
        
        public async Task AddAsync(User user)
        {
            await _context.Users.AddAsync(user);
        }
        
        public void Update(User user)
        {
            _context.Entry(user).State = EntityState.Modified;
        }
        
        public void Remove(User user)
        {
            _context.Users.Remove(user);
        }
    }
    
    // Unit of Work implementation
    public class AuthDbContext : DbContext, IUnitOfWork
    {
        private IDbContextTransaction _currentTransaction;
        private readonly IEventDispatcher _eventDispatcher;
        
        public AuthDbContext(DbContextOptions<AuthDbContext> options, IEventDispatcher eventDispatcher)
            : base(options)
        {
            _eventDispatcher = eventDispatcher;
        }
        
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        
        public async Task BeginTransactionAsync()
        {
            if (_currentTransaction != null)
                return;
            
            _currentTransaction = await Database.BeginTransactionAsync();
        }
        
        public async Task CommitTransactionAsync()
        {
            try
            {
                await SaveChangesAsync();
                _currentTransaction?.Commit();
            }
            catch
            {
                await RollbackTransactionAsync();
                throw;
            }
            finally
            {
                _currentTransaction?.Dispose();
                _currentTransaction = null;
            }
        }
        
        public async Task RollbackTransactionAsync()
        {
            try
            {
                _currentTransaction?.Rollback();
            }
            finally
            {
                _currentTransaction?.Dispose();
                _currentTransaction = null;
            }
        }
        
        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            // Dispatch domain events before saving
            await DispatchDomainEventsAsync();
            
            return await base.SaveChangesAsync(cancellationToken);
        }
        
        private async Task DispatchDomainEventsAsync()
        {
            var domainEntities = ChangeTracker
                .Entries<AggregateRoot>()
                .Where(x => x.Entity.DomainEvents.Any())
                .ToList();
            
            var domainEvents = domainEntities
                .SelectMany(x => x.Entity.DomainEvents)
                .ToList();
            
            domainEntities.ForEach(entity => entity.Entity.ClearDomainEvents());
            
            foreach (var domainEvent in domainEvents)
            {
                await _eventDispatcher.DispatchAsync(domainEvent);
            }
        }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
        }
    }
}
```

### 4. Dependency Injection Pattern

```csharp
// Service registration patterns
namespace AuthApi.Configuration
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthenticationServices(
            this IServiceCollection services, 
            IConfiguration configuration)
        {
            // Core services
            services.AddScoped<IPasswordService, PasswordService>();
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IEmailService, EmailService>();
            
            // Repositories
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<IRoleRepository, RoleRepository>();
            services.AddScoped<IPermissionRepository, PermissionRepository>();
            
            // Use cases / Command handlers
            services.AddScoped<IAuthenticateUserUseCase, AuthenticateUserUseCase>();
            services.AddScoped<ICreateUserUseCase, CreateUserUseCase>();
            services.AddScoped<IChangePasswordUseCase, ChangePasswordUseCase>();
            
            // Query handlers
            services.AddScoped<IQueryHandler<GetUserByIdQuery, UserDto>, GetUserByIdQueryHandler>();
            services.AddScoped<IQueryHandler<GetUserPermissionsQuery, List<string>>, GetUserPermissionsQueryHandler>();
            
            // Event handlers
            services.AddScoped<IEventHandler<UserRegisteredEvent>, UserRegisteredEventHandler>();
            services.AddScoped<IEventHandler<PasswordChangedEvent>, PasswordChangedEventHandler>();
            
            // Infrastructure services
            services.AddScoped<IEventDispatcher, EventDispatcher>();
            services.AddScoped<IEventBus, EventBus>();
            
            return services;
        }
        
        public static IServiceCollection AddAuthorizationServices(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddAuthorization(options =>
            {
                // Policy-based authorization
                options.AddPolicy("RequireAdminRole", policy =>
                    policy.RequireRole("Administrator"));
                
                options.AddPolicy("RequireManagerRole", policy =>
                    policy.RequireRole("Manager", "Administrator"));
                
                // Custom requirements
                options.AddPolicy("CanManageUsers", policy =>
                    policy.Requirements.Add(new PermissionRequirement("user.manage")));
                
                options.AddPolicy("CanAccessResource", policy =>
                    policy.Requirements.Add(new ResourceAccessRequirement()));
            });
            
            // Authorization handlers
            services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
            services.AddScoped<IAuthorizationHandler, ResourceAccessAuthorizationHandler>();
            
            return services;
        }
        
        public static IServiceCollection AddSecurityServices(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            // Rate limiting
            services.AddMemoryCache();
            services.AddStackExchangeRedisCache(options =>
                options.Configuration = configuration.GetConnectionString("Redis"));
            
            services.AddScoped<IRateLimitingService, RateLimitingService>();
            
            // Input validation
            services.AddScoped<IInputValidationService, InputValidationService>();
            services.AddScoped<IOutputEncodingService, OutputEncodingService>();
            
            // Security monitoring
            services.AddScoped<ISecurityEventLogger, SecurityEventLogger>();
            services.AddScoped<IThreatDetectionService, ThreatDetectionService>();
            
            // Session management
            services.AddScoped<ISessionService, SessionService>();
            services.AddScoped<ISessionSecurityService, SessionSecurityService>();
            
            return services;
        }
    }
    
    // Factory pattern for complex service creation
    public interface IAuthServiceFactory
    {
        IAuthenticationService CreateAuthenticationService(AuthenticationProvider provider);
        IAuthorizationService CreateAuthorizationService(AuthorizationStrategy strategy);
    }
    
    public class AuthServiceFactory : IAuthServiceFactory
    {
        private readonly IServiceProvider _serviceProvider;
        
        public AuthServiceFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }
        
        public IAuthenticationService CreateAuthenticationService(AuthenticationProvider provider)
        {
            return provider switch
            {
                AuthenticationProvider.Local => _serviceProvider.GetRequiredService<LocalAuthenticationService>(),
                AuthenticationProvider.OAuth => _serviceProvider.GetRequiredService<OAuthAuthenticationService>(),
                AuthenticationProvider.SAML => _serviceProvider.GetRequiredService<SamlAuthenticationService>(),
                AuthenticationProvider.Certificate => _serviceProvider.GetRequiredService<CertificateAuthenticationService>(),
                _ => throw new ArgumentException($"Unknown authentication provider: {provider}")
            };
        }
        
        public IAuthorizationService CreateAuthorizationService(AuthorizationStrategy strategy)
        {
            return strategy switch
            {
                AuthorizationStrategy.RoleBased => _serviceProvider.GetRequiredService<RoleBasedAuthorizationService>(),
                AuthorizationStrategy.PermissionBased => _serviceProvider.GetRequiredService<PermissionBasedAuthorizationService>(),
                AuthorizationStrategy.PolicyBased => _serviceProvider.GetRequiredService<PolicyBasedAuthorizationService>(),
                AuthorizationStrategy.AttributeBased => _serviceProvider.GetRequiredService<AttributeBasedAuthorizationService>(),
                _ => throw new ArgumentException($"Unknown authorization strategy: {strategy}")
            };
        }
    }
}
```

### 5. Decorator Pattern for Cross-Cutting Concerns

```csharp
// Logging decorator
namespace AuthApplication.Decorators
{
    public class LoggingCommandHandlerDecorator<TCommand, TResult> : ICommandHandler<TCommand, TResult>
        where TCommand : ICommand<TResult>
    {
        private readonly ICommandHandler<TCommand, TResult> _inner;
        private readonly ILogger<LoggingCommandHandlerDecorator<TCommand, TResult>> _logger;
        
        public LoggingCommandHandlerDecorator(
            ICommandHandler<TCommand, TResult> inner,
            ILogger<LoggingCommandHandlerDecorator<TCommand, TResult>> logger)
        {
            _inner = inner;
            _logger = logger;
        }
        
        public async Task<TResult> Handle(TCommand command, CancellationToken cancellationToken)
        {
            var commandName = typeof(TCommand).Name;
            var stopwatch = Stopwatch.StartNew();
            
            _logger.LogInformation("Executing command {CommandName}", commandName);
            
            try
            {
                var result = await _inner.Handle(command, cancellationToken);
                
                stopwatch.Stop();
                _logger.LogInformation("Command {CommandName} executed successfully in {ElapsedMs}ms", 
                    commandName, stopwatch.ElapsedMilliseconds);
                
                return result;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Command {CommandName} failed after {ElapsedMs}ms", 
                    commandName, stopwatch.ElapsedMilliseconds);
                throw;
            }
        }
    }
    
    // Validation decorator
    public class ValidationCommandHandlerDecorator<TCommand, TResult> : ICommandHandler<TCommand, TResult>
        where TCommand : ICommand<TResult>
    {
        private readonly ICommandHandler<TCommand, TResult> _inner;
        private readonly IEnumerable<IValidator<TCommand>> _validators;
        
        public ValidationCommandHandlerDecorator(
            ICommandHandler<TCommand, TResult> inner,
            IEnumerable<IValidator<TCommand>> validators)
        {
            _inner = inner;
            _validators = validators;
        }
        
        public async Task<TResult> Handle(TCommand command, CancellationToken cancellationToken)
        {
            var validationContext = new ValidationContext<TCommand>(command);
            var validationResults = await Task.WhenAll(
                _validators.Select(v => v.ValidateAsync(validationContext, cancellationToken)));
            
            var failures = validationResults
                .SelectMany(r => r.Errors)
                .Where(f => f != null)
                .ToList();
            
            if (failures.Any())
            {
                throw new ValidationException(failures);
            }
            
            return await _inner.Handle(command, cancellationToken);
        }
    }
    
    // Caching decorator
    public class CachingQueryHandlerDecorator<TQuery, TResult> : IQueryHandler<TQuery, TResult>
        where TQuery : IQuery<TResult>
    {
        private readonly IQueryHandler<TQuery, TResult> _inner;
        private readonly IMemoryCache _cache;
        private readonly ICacheKeyGenerator _keyGenerator;
        private readonly TimeSpan _cacheDuration;
        
        public CachingQueryHandlerDecorator(
            IQueryHandler<TQuery, TResult> inner,
            IMemoryCache cache,
            ICacheKeyGenerator keyGenerator,
            TimeSpan cacheDuration)
        {
            _inner = inner;
            _cache = cache;
            _keyGenerator = keyGenerator;
            _cacheDuration = cacheDuration;
        }
        
        public async Task<TResult> Handle(TQuery query, CancellationToken cancellationToken)
        {
            var cacheKey = _keyGenerator.GenerateKey(query);
            
            if (_cache.TryGetValue(cacheKey, out TResult cachedResult))
            {
                return cachedResult;
            }
            
            var result = await _inner.Handle(query, cancellationToken);
            
            _cache.Set(cacheKey, result, _cacheDuration);
            
            return result;
        }
    }
    
    // Security audit decorator
    public class SecurityAuditCommandHandlerDecorator<TCommand, TResult> : ICommandHandler<TCommand, TResult>
        where TCommand : ICommand<TResult>
    {
        private readonly ICommandHandler<TCommand, TResult> _inner;
        private readonly ISecurityAuditService _auditService;
        private readonly ICurrentUserService _currentUserService;
        
        public async Task<TResult> Handle(TCommand command, CancellationToken cancellationToken)
        {
            var userId = _currentUserService.GetCurrentUserId();
            var commandName = typeof(TCommand).Name;
            
            await _auditService.LogCommandExecutionAsync(new SecurityAuditEntry
            {
                UserId = userId,
                Action = commandName,
                Timestamp = DateTime.UtcNow,
                CommandData = JsonSerializer.Serialize(command)
            });
            
            try
            {
                var result = await _inner.Handle(command, cancellationToken);
                
                await _auditService.LogCommandSuccessAsync(new SecurityAuditEntry
                {
                    UserId = userId,
                    Action = $"{commandName}_SUCCESS",
                    Timestamp = DateTime.UtcNow
                });
                
                return result;
            }
            catch (Exception ex)
            {
                await _auditService.LogCommandFailureAsync(new SecurityAuditEntry
                {
                    UserId = userId,
                    Action = $"{commandName}_FAILURE",
                    Timestamp = DateTime.UtcNow,
                    ErrorMessage = ex.Message
                });
                
                throw;
            }
        }
    }
}

// Decorator registration
public static class DecoratorExtensions
{
    public static IServiceCollection AddCommandHandlerDecorators(this IServiceCollection services)
    {
        services.Decorate(typeof(ICommandHandler<,>), typeof(LoggingCommandHandlerDecorator<,>));
        services.Decorate(typeof(ICommandHandler<,>), typeof(ValidationCommandHandlerDecorator<,>));
        services.Decorate(typeof(ICommandHandler<,>), typeof(SecurityAuditCommandHandlerDecorator<,>));
        
        return services;
    }
    
    public static IServiceCollection AddQueryHandlerDecorators(this IServiceCollection services)
    {
        services.Decorate(typeof(IQueryHandler<,>), typeof(CachingQueryHandlerDecorator<,>));
        services.Decorate(typeof(IQueryHandler<,>), typeof(LoggingQueryHandlerDecorator<,>));
        
        return services;
    }
}
```

### 6. Strategy Pattern for Authentication Methods

```csharp
// Strategy pattern for different authentication methods
namespace AuthApplication.Strategies
{
    public interface IAuthenticationStrategy
    {
        string ProviderName { get; }
        Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request);
        Task<bool> ValidateAsync(string token);
        Task<UserInfo> GetUserInfoAsync(string token);
    }
    
    public class LocalAuthenticationStrategy : IAuthenticationStrategy
    {
        public string ProviderName => "Local";
        
        private readonly IUserRepository _userRepository;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        
        public LocalAuthenticationStrategy(
            IUserRepository userRepository,
            IPasswordService passwordService,
            ITokenService tokenService)
        {
            _userRepository = userRepository;
            _passwordService = passwordService;
            _tokenService = tokenService;
        }
        
        public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
        {
            var user = await _userRepository.FindByEmailAsync(new Email(request.Username));
            if (user == null)
                return AuthenticationResult.Failed("Invalid credentials");
            
            if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
                return AuthenticationResult.Failed("Invalid credentials");
            
            var token = await _tokenService.GenerateTokenAsync(new TokenRequest
            {
                UserId = user.Id.Value.ToString(),
                Email = user.Email.Value,
                Roles = user.Roles.Select(r => r.Role.Name).ToList()
            });
            
            return AuthenticationResult.Success(token);
        }
        
        public async Task<bool> ValidateAsync(string token)
        {
            return await _tokenService.ValidateTokenAsync(token);
        }
        
        public async Task<UserInfo> GetUserInfoAsync(string token)
        {
            var claims = await _tokenService.GetClaimsFromTokenAsync(token);
            var userId = claims.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(userId))
                return null;
            
            var user = await _userRepository.FindByIdAsync(new UserId(Guid.Parse(userId)));
            
            return new UserInfo
            {
                Id = user.Id.Value.ToString(),
                Email = user.Email.Value,
                Roles = user.Roles.Select(r => r.Role.Name).ToList()
            };
        }
    }
    
    public class OAuthAuthenticationStrategy : IAuthenticationStrategy
    {
        public string ProviderName => "OAuth";
        
        private readonly IOAuthService _oauthService;
        private readonly IUserRepository _userRepository;
        private readonly ITokenService _tokenService;
        
        public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
        {
            // Exchange authorization code for access token
            var tokenResponse = await _oauthService.ExchangeCodeForTokenAsync(request.Code);
            if (!tokenResponse.IsSuccess)
                return AuthenticationResult.Failed("OAuth authentication failed");
            
            // Get user info from OAuth provider
            var userInfo = await _oauthService.GetUserInfoAsync(tokenResponse.AccessToken);
            if (userInfo == null)
                return AuthenticationResult.Failed("Failed to retrieve user information");
            
            // Find or create local user
            var user = await FindOrCreateUserAsync(userInfo);
            
            // Generate our own token
            var token = await _tokenService.GenerateTokenAsync(new TokenRequest
            {
                UserId = user.Id.Value.ToString(),
                Email = user.Email.Value,
                Roles = user.Roles.Select(r => r.Role.Name).ToList()
            });
            
            return AuthenticationResult.Success(token);
        }
        
        private async Task<User> FindOrCreateUserAsync(OAuthUserInfo userInfo)
        {
            var email = new Email(userInfo.Email);
            var user = await _userRepository.FindByEmailAsync(email);
            
            if (user == null)
            {
                // Create new user for OAuth authentication
                user = new User(email, null); // No password for OAuth users
                await _userRepository.AddAsync(user);
                await _userRepository.UnitOfWork.SaveChangesAsync();
            }
            
            return user;
        }
        
        public async Task<bool> ValidateAsync(string token)
        {
            return await _tokenService.ValidateTokenAsync(token);
        }
        
        public async Task<UserInfo> GetUserInfoAsync(string token)
        {
            // Implementation similar to LocalAuthenticationStrategy
            return null;
        }
    }
    
    // Context that uses strategies
    public class AuthenticationContext
    {
        private readonly Dictionary<string, IAuthenticationStrategy> _strategies;
        
        public AuthenticationContext(IEnumerable<IAuthenticationStrategy> strategies)
        {
            _strategies = strategies.ToDictionary(s => s.ProviderName, s => s);
        }
        
        public async Task<AuthenticationResult> AuthenticateAsync(string provider, AuthenticationRequest request)
        {
            if (!_strategies.TryGetValue(provider, out var strategy))
                throw new ArgumentException($"Unknown authentication provider: {provider}");
            
            return await strategy.AuthenticateAsync(request);
        }
        
        public async Task<bool> ValidateAsync(string provider, string token)
        {
            if (!_strategies.TryGetValue(provider, out var strategy))
                return false;
            
            return await strategy.ValidateAsync(token);
        }
        
        public IEnumerable<string> GetSupportedProviders()
        {
            return _strategies.Keys;
        }
    }
}
```

### 7. Event Sourcing Pattern for Audit Trail

```csharp
// Event sourcing for authentication events
namespace AuthDomain.Events
{
    public abstract class DomainEvent
    {
        public Guid Id { get; } = Guid.NewGuid();
        public DateTime Timestamp { get; } = DateTime.UtcNow;
        public int Version { get; set; }
    }
    
    public class UserAuthenticatedEvent : DomainEvent
    {
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public AuthenticationMethod Method { get; set; }
        public bool Success { get; set; }
        public string FailureReason { get; set; }
    }
    
    public class PasswordChangedEvent : DomainEvent
    {
        public Guid UserId { get; set; }
        public string ChangedBy { get; set; }
        public string Reason { get; set; }
    }
    
    public class RoleAssignedEvent : DomainEvent
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public string RoleName { get; set; }
        public string AssignedBy { get; set; }
    }
    
    public class PermissionGrantedEvent : DomainEvent
    {
        public Guid UserId { get; set; }
        public string Permission { get; set; }
        public string ResourceType { get; set; }
        public string ResourceId { get; set; }
        public string GrantedBy { get; set; }
    }
}

// Event store implementation
namespace AuthInfrastructure.EventStore
{
    public interface IEventStore
    {
        Task AppendEventsAsync(string streamId, IEnumerable<DomainEvent> events, int expectedVersion);
        Task<IEnumerable<DomainEvent>> GetEventsAsync(string streamId, int fromVersion = 0);
        Task<IEnumerable<DomainEvent>> GetEventsByTypeAsync<T>() where T : DomainEvent;
        Task<IEnumerable<DomainEvent>> GetEventsAsync(DateTime from, DateTime to);
    }
    
    public class SqlEventStore : IEventStore
    {
        private readonly EventStoreDbContext _context;
        private readonly IEventSerializer _serializer;
        
        public SqlEventStore(EventStoreDbContext context, IEventSerializer serializer)
        {
            _context = context;
            _serializer = serializer;
        }
        
        public async Task AppendEventsAsync(string streamId, IEnumerable<DomainEvent> events, int expectedVersion)
        {
            var eventEntities = events.Select((e, index) => new EventEntity
            {
                Id = Guid.NewGuid(),
                StreamId = streamId,
                EventType = e.GetType().Name,
                EventData = _serializer.Serialize(e),
                Version = expectedVersion + index + 1,
                Timestamp = e.Timestamp
            }).ToList();
            
            await _context.Events.AddRangeAsync(eventEntities);
            await _context.SaveChangesAsync();
        }
        
        public async Task<IEnumerable<DomainEvent>> GetEventsAsync(string streamId, int fromVersion = 0)
        {
            var eventEntities = await _context.Events
                .Where(e => e.StreamId == streamId && e.Version > fromVersion)
                .OrderBy(e => e.Version)
                .ToListAsync();
            
            return eventEntities.Select(e => _serializer.Deserialize(e.EventData, e.EventType));
        }
        
        public async Task<IEnumerable<DomainEvent>> GetEventsByTypeAsync<T>() where T : DomainEvent
        {
            var eventType = typeof(T).Name;
            var eventEntities = await _context.Events
                .Where(e => e.EventType == eventType)
                .OrderBy(e => e.Timestamp)
                .ToListAsync();
            
            return eventEntities.Select(e => _serializer.Deserialize(e.EventData, e.EventType));
        }
        
        public async Task<IEnumerable<DomainEvent>> GetEventsAsync(DateTime from, DateTime to)
        {
            var eventEntities = await _context.Events
                .Where(e => e.Timestamp >= from && e.Timestamp <= to)
                .OrderBy(e => e.Timestamp)
                .ToListAsync();
            
            return eventEntities.Select(e => _serializer.Deserialize(e.EventData, e.EventType));
        }
    }
    
    // Event projection for read models
    public class AuthenticationAuditProjection : IEventHandler<UserAuthenticatedEvent>
    {
        private readonly AuditDbContext _auditContext;
        
        public async Task Handle(UserAuthenticatedEvent @event, CancellationToken cancellationToken)
        {
            var auditEntry = new AuthenticationAuditEntry
            {
                Id = Guid.NewGuid(),
                UserId = @event.UserId,
                Email = @event.Email,
                IpAddress = @event.IpAddress,
                UserAgent = @event.UserAgent,
                AuthenticationMethod = @event.Method.ToString(),
                Success = @event.Success,
                FailureReason = @event.FailureReason,
                Timestamp = @event.Timestamp
            };
            
            await _auditContext.AuthenticationAudits.AddAsync(auditEntry, cancellationToken);
            await _auditContext.SaveChangesAsync(cancellationToken);
        }
    }
}
```

### 8. Configuration and Startup Patterns

```csharp
// Startup configuration
namespace AuthApi
{
    public class Startup
    {
        private readonly IConfiguration _configuration;
        
        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        public void ConfigureServices(IServiceCollection services)
        {
            // Database
            services.AddDbContext<AuthDbContext>(options =>
                options.UseSqlServer(_configuration.GetConnectionString("DefaultConnection")));
            
            // Authentication & Authorization
            services.AddAuthenticationServices(_configuration);
            services.AddAuthorizationServices(_configuration);
            services.AddSecurityServices(_configuration);
            
            // CQRS & Event handling
            services.AddCqrs();
            services.AddEventSourcing(_configuration);
            
            // Cross-cutting concerns
            services.AddCommandHandlerDecorators();
            services.AddQueryHandlerDecorators();
            
            // API
            services.AddControllers();
            services.AddApiVersioning();
            services.AddSwaggerGen();
            
            // Health checks
            services.AddHealthChecks()
                .AddDbContextCheck<AuthDbContext>()
                .AddCheck<AuthenticationHealthCheck>("authentication")
                .AddCheck<AuthorizationHealthCheck>("authorization");
        }
        
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }
            
            // Security middleware pipeline
            app.UseHttpsRedirection();
            app.UseSecurityHeaders();
            app.UseRateLimiting();
            app.UseInputValidation();
            
            // Authentication & Authorization
            app.UseAuthentication();
            app.UseAuthorization();
            
            // Routing
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapHealthChecks("/health");
            });
        }
    }
    
    // Health checks
    public class AuthenticationHealthCheck : IHealthCheck
    {
        private readonly ITokenService _tokenService;
        
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                // Test token generation and validation
                var testToken = await _tokenService.GenerateTokenAsync(new TokenRequest
                {
                    UserId = "health-check-user",
                    Roles = new[] { "Test" }
                });
                
                var isValid = await _tokenService.ValidateTokenAsync(testToken.AccessToken);
                
                return isValid 
                    ? HealthCheckResult.Healthy("Authentication service is working") 
                    : HealthCheckResult.Unhealthy("Token validation failed");
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy("Authentication service failed", ex);
            }
        }
    }
}
```

## Summary

This implementation patterns guide provides:

1. **Clean Architecture**: Separation of concerns with domain, application, and infrastructure layers
2. **CQRS Pattern**: Separate read and write operations for better scalability
3. **Repository & Unit of Work**: Data access abstraction with transaction management
4. **Dependency Injection**: Flexible service registration and resolution
5. **Decorator Pattern**: Cross-cutting concerns like logging, validation, caching
6. **Strategy Pattern**: Multiple authentication methods with pluggable strategies
7. **Event Sourcing**: Complete audit trail of authentication/authorization events
8. **Configuration Patterns**: Structured startup and health check implementations

These patterns provide a solid foundation for building scalable, maintainable, and secure authentication and authorization systems in .NET applications.

---
**End of Authentication & Authorization Learning Series**

All 21 authentication and authorization topics have been completed with comprehensive .NET code examples, security best practices, and real-world implementation patterns. This series provides a complete guide to understanding and implementing secure authentication and authorization systems in modern .NET applications.