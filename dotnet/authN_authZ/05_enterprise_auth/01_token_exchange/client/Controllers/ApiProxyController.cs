using System.Diagnostics;
using System.Net.Http.Headers;
using client.Saml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace client.Controllers
{
    [Route("[controller]")]
    public class ApiProxyController : Controller
    {
        private readonly ILogger<ApiProxyController> _logger;
        private readonly IHttpClientFactory _httpFactory;
        private readonly IApiTokenFactory _tokens;

        public ApiProxyController(ILogger<ApiProxyController> logger, IHttpClientFactory httpFactory, IApiTokenFactory tokens)
        {
            _logger = logger;
            _httpFactory = httpFactory;
            _tokens = tokens;
        }
        public IActionResult Index()
        {
            return Ok("OK");
        }

        [HttpGet("call-api")]
        public async Task<IActionResult> CallApi()
        {
            var jwt = _tokens.CreateToken(User);

            var client = _httpFactory.CreateClient("Api");
            using var req = new HttpRequestMessage(HttpMethod.Get, "WeatherForecast");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

            using var res = await client.SendAsync(req);
            var body = await res.Content.ReadAsStringAsync();

            return Content($"API status: {(int)res.StatusCode}\n\n{body}", "text/plain");
        }
    }
}