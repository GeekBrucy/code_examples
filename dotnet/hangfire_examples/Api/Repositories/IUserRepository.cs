using Api.Models;

namespace Api.Repositories;

public interface IUserRepository
{
    Task<IReadOnlyList<User>> GetByIdsAsync(IEnumerable<int> userIds, CancellationToken ct = default);
}
