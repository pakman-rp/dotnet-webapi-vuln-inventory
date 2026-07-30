using InventoryVuln.Data;
using InventoryVuln.Models;
using Microsoft.AspNetCore.Mvc;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("api/products")]
public class ProductController : ControllerBase
{
    private readonly AppDbContext _db;

    public ProductController(AppDbContext db)
    {
        _db = db;
    }

    [HttpGet("{id}")]
    public IActionResult GetProduct(int id)
    {
        // VULN (CWE-639): IDOR-adjacent — no ownership/role check; any caller
        // can view CostPrice (internal-only field) for any product.
        var product = _db.Products.Find(id);
        if (product is null) return NotFound();
        return Ok(product);
    }

    /// <summary>
    /// CreateProduct — VULN (CWE-915): Mass Assignment / Over-posting. The
    /// entire `Product` entity is bound directly from the request body, so a
    /// client can set `IsApproved = true` and `CostPrice` themselves, fields
    /// that should only ever be set by a server-side approval workflow.
    /// </summary>
    [HttpPost]
    public IActionResult CreateProduct([FromBody] Product product) // VULN sink: binds full entity, not a restricted DTO
    {
        _db.Products.Add(product);
        _db.SaveChanges();
        return CreatedAtAction(nameof(GetProduct), new { id = product.Id }, product);
    }

    /// <summary>
    /// UpdateProduct — same Mass Assignment issue on update: a client can
    /// silently flip IsApproved or rewrite CostPrice on an existing product
    /// they don't even own.
    /// </summary>
    [HttpPut("{id}")]
    public IActionResult UpdateProduct(int id, [FromBody] Product updated) // VULN sink
    {
        var existing = _db.Products.Find(id);
        if (existing is null) return NotFound();

        // VULN: every field overwritten wholesale, including IsApproved/CostPrice/OwnerUserId
        existing.Sku = updated.Sku;
        existing.Name = updated.Name;
        existing.RetailPrice = updated.RetailPrice;
        existing.CostPrice = updated.CostPrice;       // should be admin-only
        existing.IsApproved = updated.IsApproved;      // should be admin-only
        existing.Quantity = updated.Quantity;
        existing.OwnerUserId = updated.OwnerUserId;    // should never be client-settable

        _db.SaveChanges();
        return Ok(existing);
    }

    /// <summary>
    /// RedirectToSupplier — VULN (CWE-601): Open Redirect, target taken
    /// directly from a query parameter.
    /// </summary>
    [HttpGet("redirect")]
    public IActionResult RedirectToSupplier([FromQuery] string url)
    {
        return Redirect(url); // VULN sink
    }
}
