using API.Data;
using API.DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        private readonly MyDbContext _context;
        public TestController(MyDbContext context)
        {
            _context = context;
        }
        [HttpPost]
        public async Task<ActionResult<object>> FullTextQuery(FullTextPayload payload)
        {
            var query = _context.SearchTargets
            .Where(st => EF.Functions.Contains(st.Texts, payload.FreeText));
            return Ok(await query.ToListAsync());
        }
    }
}