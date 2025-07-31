using API.Data;
using API.DTOs;
using API.Models;
using API.Services.Search;
using API.Utils;

namespace API.Tests.TestHelpers
{
    public class TestableSearchService : ISearchService
    {
        private readonly MyDbContext _context;

        public TestableSearchService(MyDbContext context)
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

            return _context.SearchTargets.Where(st => st.Texts.Contains(payload.FreeText));
        }
    }
}