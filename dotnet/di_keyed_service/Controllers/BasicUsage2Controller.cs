using di_keyed_service.Services._01_Fundamental;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class BasicUsage2Controller : ControllerBase
    {
        private readonly IBasic _basic1;
        private readonly IBasic _basic2;

        public BasicUsage2Controller(
            [FromKeyedServices("Basic1")] IBasic basic1,
            [FromKeyedServices("Basic2")] IBasic basic2)
        {
            _basic1 = basic1;
            _basic2 = basic2;
        }

        [HttpGet]
        public IActionResult TestKeyedServices()
        {
            _basic1.Run();
            _basic2.Run();

            return Ok(new { Message = "FromKeyedServices approach executed successfully" });
        }
    }
}