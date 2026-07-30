using Microsoft.AspNetCore.Mvc;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("api/invoices")]
public class InvoiceUploadController : ControllerBase
{
    private const string UploadDir = "./uploads/";

    /// <summary>
    /// UploadInvoice — VULN (CWE-434): Unrestricted File Upload. No
    /// extension allow-list, no content-type validation, no size limit,
    /// no AV scan.
    /// VULN (CWE-22): Path Traversal — the original file name is used
    /// verbatim to build the destination path.
    /// </summary>
    [HttpPost("upload")]
    public async Task<IActionResult> UploadInvoice(IFormFile file)
    {
        if (file is null || file.Length == 0) return BadRequest(new { error = "file required" });

        var destPath = Path.Combine(UploadDir, file.FileName); // VULN sink: unsanitized filename
        Directory.CreateDirectory(UploadDir);
        await using var stream = System.IO.File.Create(destPath);
        await file.CopyToAsync(stream);

        return Ok(new { status = "uploaded", path = destPath });
    }
}
