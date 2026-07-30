using InventoryVuln.Models;
using Microsoft.EntityFrameworkCore;

namespace InventoryVuln.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<ApplicationUser> Users => Set<ApplicationUser>();
    public DbSet<Product> Products => Set<Product>();
    public DbSet<PurchaseOrder> PurchaseOrders => Set<PurchaseOrder>();
}
