using di_keyed_service.Services._01_Fundamental;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class BasicUsage3Controller : ControllerBase
    {
        private readonly Dictionary<string, IBasic> _basicServices;

        public BasicUsage3Controller(IEnumerable<IBasic> basicServices)
        {
            _basicServices = basicServices.ToDictionary(h => h.Key, h => h);
        }

        [HttpGet]
        public IActionResult TestKeyedService()
        {
            foreach (var item in _basicServices.Values)
            {
                item.Run();
            }
            return Ok(new { Message = "Dictionary approach executed successfully", Services = _basicServices.Keys });
        }
    }
}