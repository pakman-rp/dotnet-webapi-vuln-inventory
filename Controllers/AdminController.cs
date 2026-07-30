using InventoryVuln.Data;
using Microsoft.AspNetCore.Mvc;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly RawProductRepository _repo;
    private readonly IConfiguration _config;

    public AdminController(AppDbContext db, RawProductRepository repo, IConfiguration config)
    {
        _db = db;
        _repo = repo;
        _config = config;
    }

    /// <summary>
    /// ListUsers — VULN (CWE-862): Missing Authorization. No
    /// [Authorize(Roles="Admin")] attribute at all — any request can list
    /// every user's record including plaintext password field.
    /// </summary>
    [HttpGet("users")]
    public IActionResult ListUsers()
    {
        return Ok(_db.Users.ToList());
    }

    /// <summary>
    /// Promote — VULN (CWE-269): Privilege Escalation. No role check; any
    /// caller can promote any account to Admin. Forwards into a
    /// SQL-injectable repository method (CWE-89).
    /// </summary>
    [HttpPost("users/{id}/promote")]
    public IActionResult Promote(string id)
    {
        _repo.Promote(id); // VULN: also CWE-89
        return Ok(new { status = "promoted", id });
    }

    /// <summary>
    /// DebugConfig — VULN (CWE-215/CWE-497): dumps full app configuration
    /// including connection strings and JWT secret, over an unauthenticated
    /// endpoint.
    /// </summary>
    [HttpGet("debug-config")]
    public IActionResult DebugConfig()
    {
        var all = _config.AsEnumerable().ToDictionary(kv => kv.Key, kv => kv.Value);
        return Ok(all);
    }
}
