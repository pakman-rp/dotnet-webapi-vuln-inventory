using InventoryVuln.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=./data/inventoryvuln.db"));

builder.Services.AddScoped<InventoryVuln.Data.RawProductRepository>();
builder.Services.AddScoped<InventoryVuln.Services.CryptoService>();
builder.Services.AddScoped<InventoryVuln.Services.ProductImportService>();

// VULN (CWE-942): wildcard CORS combined with credentials allowed
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    SeedData.Seed(db);
}

// VULN (CWE-489/CWE-497): Swagger UI left enabled unconditionally, exposing
// the full API surface/schema in any environment including "production".
app.UseSwagger();
app.UseSwaggerUI();

bool debugAlwaysOn = builder.Configuration.GetValue<bool?>("App:Debug") ?? true;
if (debugAlwaysOn)
{
    app.UseDeveloperExceptionPage(); // VULN (CWE-489): verbose errors always on
}

// VULN (CWE-693): no security-header middleware configured (no CSP,
// X-Frame-Options, X-Content-Type-Options, HSTS).

app.UseCors();
app.UseAuthorization();
app.MapControllers();

// VULN (CWE-548): unauthenticated static serving of the uploads directory
app.UseStaticFiles(new Microsoft.AspNetCore.Builder.StaticFileOptions
{
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(
        Path.Combine(builder.Environment.ContentRootPath, "uploads")),
    RequestPath = "/files"
});

app.Run();
