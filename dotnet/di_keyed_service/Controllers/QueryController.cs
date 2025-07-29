using di_keyed_service.Models;
using di_keyed_service.Services._04_QueryBuilder;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class QueryController : ControllerBase
    {
        private readonly IQueryService _queryService;

        public QueryController(IQueryService queryService)
        {
            _queryService = queryService;
        }

        [HttpPost]
        public IActionResult ExecuteQuery([FromBody] SampleModel request)
        {
            var result = _queryService.ExecuteQuery(request);
            
            return Ok(new
            {
                Message = "Dynamic query executed successfully",
                AppliedPredicates = result.AppliedPredicates,
                Results = new
                {
                    ModelA = result.ModelAResults.Select(x => new { x.Id, x.PropertyA, x.IsActive }),
                    ModelB = result.ModelBResults.Select(x => new { x.Id, x.PropertyB, x.Amount }),
                    ModelC = result.ModelCResults.Select(x => new { x.Id, x.PropertyC, x.Category }),
                    ModelD = result.ModelDResults.Select(x => new { x.Id, x.PropertyD, x.Status })
                },
                TotalResults = result.ModelAResults.Count + result.ModelBResults.Count + 
                              result.ModelCResults.Count + result.ModelDResults.Count,
                Pattern = "Keyed DI + Expression Trees for Dynamic Query Building"
            });
        }

        [HttpGet]
        public IActionResult GetSampleRequest()
        {
            return Ok(new SampleModel
            {
                MyProperty1 = "Hello", // Will filter ModelA where PropertyA contains "Hello"
                MyProperty2 = 20,      // Will filter ModelB where PropertyB >= 20
                MyProperty3 = new[] { 3, 4 }, // Will filter ModelC where PropertyC intersects [3,4]
                MyProperty4 = true     // Will filter ModelD where PropertyD == true
            });
        }
    }
}