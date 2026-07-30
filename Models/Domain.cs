namespace InventoryVuln.Models;

public class ApplicationUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;

    // VULN (CWE-256): password stored in plaintext, no hashing anywhere in the model
    public string Password { get; set; } = string.Empty;

    public string Role { get; set; } = "User";
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// Product — VULN (CWE-915): Improper Control of Dynamically-Managed
/// Attributes (Mass Assignment). Controllers bind this entity directly from
/// the request body ([FromBody] Product) instead of a restricted DTO, so a
/// client can set IsApproved/CostPrice/OwnerUserId fields that should only
/// ever be set server-side or by an Admin.
/// </summary>
public class Product
{
    public int Id { get; set; }
    public string Sku { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public decimal RetailPrice { get; set; }

    // Should never be client-settable — internal cost basis
    public decimal CostPrice { get; set; }

    // Should only ever be set by an Admin approval workflow
    public bool IsApproved { get; set; }

    public int Quantity { get; set; }
    public int OwnerUserId { get; set; } // whichever clerk created it
}

public class PurchaseOrder
{
    public int Id { get; set; }
    public int ProductId { get; set; }
    public int Quantity { get; set; }
    public string Notes { get; set; } = string.Empty; // stored-XSS-style sink target in reports
    public string Status { get; set; } = "Pending";
}
