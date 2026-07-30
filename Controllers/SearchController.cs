using InventoryVuln.Data;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("api/products")]
public class SearchController : ControllerBase
{
    private readonly RawProductRepository _repo;
    private static readonly HttpClient _http = new();

    public SearchController(RawProductRepository repo)
    {
        _repo = repo;
    }

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q, [FromQuery] string? format)
    {
        var results = _repo.Search(q); // VULN: CWE-89

        if (format == "html")
        {
            // VULN (CWE-79): Reflected XSS — the raw search term is
            // interpolated directly into an HTML response with no encoding.
            var body = $"<h1>Results for: {q}</h1><ul>";
            foreach (var row in results)
                body += $"<li>{row["Name"]} ({row["Sku"]})</li>";
            body += "</ul>";
            return Content(body, "text/html");
        }

        return Ok(results);
    }

    /// <summary>
    /// FilterJson — VULN (CWE-943): NoSQL/document-query injection analog.
    /// The "filter" query parameter is spliced directly into a JSONPath
    /// expression evaluated against the in-memory product catalog, allowing
    /// filter-logic injection such as ?filter=true||'1'=='1'.
    /// </summary>
    [HttpGet("filter-json")]
    public IActionResult FilterJson([FromQuery] string filter)
    {
        var catalog = new JArray(
            new JObject { ["Sku"] = "SKU-1001", ["Name"] = "Steel Bracket", ["Quantity"] = 500 },
            new JObject { ["Sku"] = "SKU-1002", ["Name"] = "Copper Wire Spool", ["Quantity"] = 40 }
        );

        var result = _repo.FilterByJsonQuery(catalog, filter); // VULN sink
        return Ok(result);
    }

    /// <summary>
    /// FetchSupplierDoc — VULN (CWE-918): SSRF. The "url" parameter is passed
    /// straight to HttpClient with no allow-list.
    /// </summary>
    [HttpGet("supplier-doc-proxy")]
    public async Task<IActionResult> FetchSupplierDoc([FromQuery] string url)
    {
        var bytes = await _http.GetByteArrayAsync(url); // VULN sink
        return File(bytes, "application/octet-stream");
    }
}
