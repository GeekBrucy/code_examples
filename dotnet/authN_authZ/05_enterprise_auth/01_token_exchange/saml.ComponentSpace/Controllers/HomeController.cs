using Microsoft.AspNetCore.Mvc;

namespace saml.ComponentSpace.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
