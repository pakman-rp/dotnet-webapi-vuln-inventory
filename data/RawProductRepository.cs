using Microsoft.Data.Sqlite;
using Newtonsoft.Json.Linq;

namespace InventoryVuln.Data;

/// <summary>
/// Raw ADO.NET + dynamic-query data access used specifically to demonstrate
/// injection classes, alongside the safe EF Core LINQ access used elsewhere.
/// </summary>
public class RawProductRepository
{
    private readonly string _connectionString;

    public RawProductRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Default") ?? "Data Source=./data/inventoryvuln.db";
    }

    /// <summary>
    /// Search — VULN (CWE-89): SQL Injection. The search term is concatenated
    /// directly into the query text instead of using a parameterized command.
    /// </summary>
    public List<Dictionary<string, object>> Search(string term)
    {
        var results = new List<Dictionary<string, object>>();
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT Id, Sku, Name, RetailPrice, Quantity FROM Products WHERE Name LIKE '%{term}%'"; // VULN sink
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = new Dictionary<string, object>();
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.GetValue(i);
            results.Add(row);
        }
        return results;
    }

    /// <summary>
    /// LoginRaw — VULN (CWE-89): SQL Injection in an authentication path.
    /// </summary>
    public Dictionary<string, object>? LoginRaw(string username, string password)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT Id, Username, Role FROM Users WHERE Username = '{username}' AND Password = '{password}'"; // VULN sink
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            var row = new Dictionary<string, object>();
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.GetValue(i);
            return row;
        }
        return null;
    }

    public void Promote(string id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"UPDATE Users SET Role = 'Admin' WHERE Id = {id}"; // VULN sink: CWE-89
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// FilterByJsonQuery — VULN (CWE-943): NoSQL/Document-Query Injection
    /// analog. A client-supplied filter fragment is spliced directly into a
    /// JSONPath-style query string evaluated against a JSON document set,
    /// mirroring the same "build a query from raw untrusted input" mistake
    /// commonly seen against MongoDB/Cosmos DB in .NET services.
    /// </summary>
    public JToken? FilterByJsonQuery(JArray productsAsJson, string rawFilterFragment)
    {
        // VULN sink: rawFilterFragment (e.g. from a query parameter) is
        // concatenated directly into a JSONPath expression with no escaping,
        // allowing filter-logic injection such as: "true || '1'=='1"
        string jsonPath = $"$[?({rawFilterFragment})]";
        return productsAsJson.SelectToken(jsonPath);
    }
}
