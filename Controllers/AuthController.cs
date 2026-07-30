using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using InventoryVuln.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace InventoryVuln.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly RawProductRepository _repo;

    // VULN (CWE-798): hardcoded JWT signing secret
    private const string JwtSecret = "SuperSecretJWT";

    // VULN (CWE-798): hardcoded backdoor admin account
    private const string BackdoorUser = "admin";
    private const string BackdoorPass = "admin123";

    public AuthController(ILogger<AuthController> logger, RawProductRepository repo)
    {
        _logger = logger;
        _repo = repo;
    }

    public record LoginRequest(string Username, string Password);

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        // VULN (CWE-532): logging raw credentials
        _logger.LogInformation("Login attempt username={Username} password={Password}", req.Username, req.Password);

        string role;
        if (req.Username == BackdoorUser && req.Password == BackdoorPass)
        {
            role = "Admin"; // VULN: hardcoded backdoor bypasses the database entirely
        }
        else
        {
            var row = _repo.LoginRaw(req.Username, req.Password); // VULN: SQLi
            if (row is null) return Unauthorized(new { error = "invalid credentials" });
            role = row["Role"]?.ToString() ?? "User";
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, req.Username),
            new Claim(ClaimTypes.Role, role),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret)); // VULN (CWE-798)
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(24), // VULN: no rotation/refresh
            signingCredentials: creds);

        var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);
        _logger.LogInformation("Issued token for {Username}: {Token}", req.Username, tokenStr); // VULN (CWE-532)

        return Ok(new { token = tokenStr, role });
    }

    public record RegisterRequest(string Username, string Password, string Email);

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest req)
    {
        // VULN (CWE-521): no password policy enforcement whatsoever
        _logger.LogInformation("Registering user {Username} with password {Password}", req.Username, req.Password); // VULN (CWE-532)
        return Created("", new { status = "registered", username = req.Username });
    }
}
