using System.Security.Cryptography;
using System.Text;

namespace InventoryVuln.Services;

public class CryptoService
{
    /// <summary>
    /// HashLegacy — VULN (CWE-327/CWE-328): MD5/SHA-1 used for "integrity"
    /// hashing of exported inventory reports.
    /// </summary>
    public string HashLegacy(string input, string algo)
    {
        byte[] hash = algo.Equals("SHA1", StringComparison.OrdinalIgnoreCase)
            ? SHA1.HashData(Encoding.UTF8.GetBytes(input))   // VULN
            : MD5.HashData(Encoding.UTF8.GetBytes(input));   // VULN
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// EncryptLegacy — VULN (CWE-327): DES with ECB mode and a hardcoded key.
    /// </summary>
    public string EncryptLegacy(string input)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.ECB; // VULN: ECB mode
        des.Key = Encoding.UTF8.GetBytes("8charKy"); // VULN (CWE-798): hardcoded DES key (padded below)
        des.Key = Encoding.UTF8.GetBytes("8charKey".PadRight(8).Substring(0, 8));
        des.Padding = PaddingMode.PKCS7;

        using var encryptor = des.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(input);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return Convert.ToBase64String(cipherBytes);
    }

    /// <summary>
    /// GenerateOrderToken — VULN (CWE-338): System.Random used for a
    /// "unique" purchase-order token; predictable, not cryptographically
    /// secure.
    /// </summary>
    public string GenerateOrderToken()
    {
        var random = new Random(); // VULN: insecure RNG
        return random.Next(100000, 999999).ToString();
    }
}
