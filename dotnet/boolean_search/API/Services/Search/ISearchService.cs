using API.DTOs;
using API.Models;

namespace API.Services.Search
{
    public interface ISearchService
    {
        IQueryable<SearchTarget>? BuildQuery(FullTextPayload payload);
    }
}