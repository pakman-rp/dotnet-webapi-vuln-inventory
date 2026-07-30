using InventoryVuln.Data;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace InventoryVuln.Tests;

public class RawProductRepositoryTests : IDisposable
{
    private readonly SqliteConnection _keepAliveConnection;
    private readonly RawProductRepository _repo;
    private const string ConnStr = "Data Source=:memory:?cache=shared";

    public RawProductRepositoryTests()
    {
        _keepAliveConnection = new SqliteConnection(ConnStr);
        _keepAliveConnection.Open();

        using (var cmd = _keepAliveConnection.CreateCommand())
        {
            cmd.CommandText = "CREATE TABLE Users (Id INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT, Password TEXT, Role TEXT)";
            cmd.ExecuteNonQuery();
        }
        using (var cmd = _keepAliveConnection.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO Users (Username, Password, Role) VALUES ('wclerk', 'Password1', 'User')";
            cmd.ExecuteNonQuery();
        }

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = ConnStr
            })
            .Build();

        _repo = new RawProductRepository(config);
    }

    [Fact]
    public void LoginRaw_ValidCredentials_ReturnsRow()
    {
        var row = _repo.LoginRaw("wclerk", "Password1");
        Assert.NotNull(row);
        Assert.Equal("wclerk", row!["Username"]);
    }

    /// <summary>
    /// Documents the injection surface: a boolean-based bypass succeeds
    /// against the intentionally vulnerable concatenated query.
    /// </summary>
    [Fact]
    public void LoginRaw_SqlInjectionBypass_Succeeds()
    {
        var row = _repo.LoginRaw("wclerk' -- ", "irrelevant");
        Assert.NotNull(row);
    }

    /// <summary>
    /// Documents the NoSQL/JSONPath-injection-style filter surface: an
    /// injected boolean-true fragment returns rows that don't match the
    /// intended (benign) filter condition.
    /// </summary>
    [Fact]
    public void FilterByJsonQuery_InjectedFragment_BypassesIntendedFilter()
    {
        var catalog = new Newtonsoft.Json.Linq.JArray(
            new Newtonsoft.Json.Linq.JObject { ["Sku"] = "SKU-1001", ["Quantity"] = 500 },
            new Newtonsoft.Json.Linq.JObject { ["Sku"] = "SKU-1002", ["Quantity"] = 40 }
        );

        // Legitimate filter: only items with Quantity > 10000 (should match nothing)
        var legit = _repo.FilterByJsonQuery(catalog, "@.Quantity > 10000");
        Assert.Null(legit);

        // Injected filter: always-true condition returns a match regardless
        var injected = _repo.FilterByJsonQuery(catalog, "true");
        Assert.NotNull(injected);
    }

    public void Dispose()
    {
        _keepAliveConnection.Dispose();
    }
}
