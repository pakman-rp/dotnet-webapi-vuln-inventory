using InventoryVuln.Services;
using Microsoft.AspNetCore.Mvc;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("api/state")]
public class StateController : ControllerBase
{
    private readonly ProductImportService _importService;
    private readonly CryptoService _cryptoService;

    public StateController(ProductImportService importService, CryptoService cryptoService)
    {
        _importService = importService;
        _cryptoService = cryptoService;
    }

    [HttpPost("import-product-xml")]
    public IActionResult ImportProductXml([FromBody] string xml)
    {
        var doc = _importService.ParseProductXml(xml); // VULN: CWE-611 XXE, see service
        return Ok(new { status = "imported", root = doc.DocumentElement?.Name });
    }

    [HttpGet("hash")]
    public IActionResult Hash([FromQuery] string input, [FromQuery] string algo = "MD5")
        => Ok(new { hash = _cryptoService.HashLegacy(input, algo) }); // VULN: CWE-327/328

    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string input)
        => Ok(new { cipher = _cryptoService.EncryptLegacy(input) }); // VULN: CWE-327 DES+ECB

    [HttpGet("order-token")]
    public IActionResult OrderToken()
        => Ok(new { token = _cryptoService.GenerateOrderToken() }); // VULN: CWE-338
}
