using InventoryVuln.Models;

namespace InventoryVuln.Data;

public static class SeedData
{
    // VULN (CWE-798): hardcoded seed credentials
    public const string AdminUser = "admin";
    public const string AdminPass = "admin123";
    public const string ClerkUser = "wclerk";
    public const string ClerkPass = "Password1";

    public static void Seed(AppDbContext db)
    {
        if (db.Users.Any()) return;

        // VULN (CWE-256): plaintext password storage
        var admin = new ApplicationUser { Username = AdminUser, Password = AdminPass, Role = "Admin", Email = "admin@inventoryvuln.example" };
        var clerk = new ApplicationUser { Username = ClerkUser, Password = ClerkPass, Role = "User", Email = "wclerk@inventoryvuln.example" };
        db.Users.AddRange(admin, clerk);
        db.SaveChanges();

        var product = new Product
        {
            Sku = "SKU-1001",
            Name = "Steel Bracket",
            RetailPrice = 4.99m,
            CostPrice = 1.20m,
            IsApproved = true,
            Quantity = 500,
            OwnerUserId = clerk.Id
        };
        db.Products.Add(product);
        db.SaveChanges();

        db.PurchaseOrders.Add(new PurchaseOrder { ProductId = product.Id, Quantity = 200, Notes = "Restock for Q3", Status = "Pending" });
        db.SaveChanges();
    }
}
