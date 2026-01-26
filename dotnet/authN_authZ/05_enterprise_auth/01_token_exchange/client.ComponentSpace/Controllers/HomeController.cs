using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace client.ComponentSpace.Controllers;

public class HomeController : Controller
{
    [Authorize]
    public IActionResult Index()
    {
        return View();
    }
}
