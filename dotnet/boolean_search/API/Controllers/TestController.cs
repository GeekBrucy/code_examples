using API.Data;
using API.DTOs;
using API.Services.Search;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ISearchService _searchService;
        public TestController(ISearchService searchService)
        {
            _searchService = searchService;
        }
        [HttpPost]
        public async Task<ActionResult<object>> FullTextQuery(FullTextPayload payload)
        {
            var query = _searchService.BuildQuery(payload);
            if (query == null) return BadRequest("Invalid payload");
            var ret = await query.ToListAsync();
            return Ok(ret);
        }
    }
}