using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using client.Models;
using Microsoft.AspNetCore.Authorization;

namespace client.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("/admin")]
    public IActionResult AdminOnly()
    {
        return Content($"Admin OK: {User.Identity?.Name}");
    }

    [Authorize(Roles = "Reader")]
    [HttpGet("/reader")]
    public IActionResult ReaderOnly()
    {
        return Content($"Reader OK: {User.Identity?.Name}");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
