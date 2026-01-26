using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace client2.Controllers;

public class HomeController : Controller
{
    [Authorize]
    public IActionResult Index() => View();
}
