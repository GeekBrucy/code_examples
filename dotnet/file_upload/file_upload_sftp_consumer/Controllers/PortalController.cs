using file_upload_sftp_consumer.Services;
using Microsoft.AspNetCore.Mvc;

namespace file_upload_sftp_consumer.Controllers;

public class PortalController : Controller
{
    private readonly ISftpBrowserService _browser;

    public PortalController(ISftpBrowserService browser)
    {
        _browser = browser;
    }

    [HttpGet("/")]
    public async Task<IActionResult> Index(string? partner, CancellationToken ct)
    {
        ViewBag.Partners = _browser.GetPartnerIds();
        ViewBag.SelectedPartner = partner;

        if (!string.IsNullOrEmpty(partner))
        {
            try
            {
                var files = await _browser.ListFilesAsync(partner, ct);
                ViewBag.Files = files;
            }
            catch (ArgumentException)
            {
                ViewBag.Error = $"Unknown partner: {partner}";
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"Failed to list files: {ex.Message}";
            }
        }

        return View();
    }

    [HttpGet("/download")]
    public async Task<IActionResult> Download(string partner, string file, CancellationToken ct)
    {
        try
        {
            var (content, fileName) = await _browser.DownloadFileAsync(partner, file, ct);
            return File(content, "application/octet-stream", fileName);
        }
        catch (FileNotFoundException)
        {
            return NotFound();
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }
}
