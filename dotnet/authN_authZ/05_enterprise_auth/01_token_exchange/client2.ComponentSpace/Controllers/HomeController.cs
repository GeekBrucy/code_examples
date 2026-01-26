using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace client2.ComponentSpace.Controllers;

public class HomeController : Controller
{
    [Authorize]
    public IActionResult Index() => View();
}
