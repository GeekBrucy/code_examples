using Api.Models;

namespace Api.Repositories;

public interface IReportRepository
{
    Task<Report> GetByIdAsync(int reportId, CancellationToken ct = default);
}
