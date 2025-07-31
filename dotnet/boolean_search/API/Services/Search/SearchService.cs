using API.Data;
using API.DTOs;
using API.Models;
using API.Utils;
using Microsoft.EntityFrameworkCore;

namespace API.Services.Search
{
    public class SearchService : ISearchService
    {
        private readonly MyDbContext _context;
        public SearchService(MyDbContext context)
        {
            _context = context;
        }
        public IQueryable<SearchTarget>? BuildQuery(FullTextPayload payload)
        {
            var result = BooleanSearchValidator.Validate(payload.FreeText);
            if (result.IsValid == false)
            {
                return null;
            }
            return _context.SearchTargets.Where(st => EF.Functions.Contains(st.Texts, payload.FreeText));
        }
    }
}