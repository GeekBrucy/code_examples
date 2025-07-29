using di_keyed_service.Services._01_Fundamental;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class BasicUsageController : ControllerBase
    {
        private readonly IServiceProvider _serviceProvider;

        public BasicUsageController(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        [HttpGet]
        public IActionResult TestBasicKeyedService()
        {
            var basic1 = _serviceProvider.GetKeyedService<IBasic>("Basic1");
            var basic2 = _serviceProvider.GetKeyedService<IBasic>("Basic2");

            basic1?.Run();
            basic2?.Run();

            return Ok(new { Message = "Both keyed services executed successfully" });
        }
    }
}