# Expected Findings — InventoryVuln (.NET Web API)

Intentional vulnerabilities seeded in this repository, for scoring SAST/SCA/
secret-scanning tool coverage during POC.

## SAST — Expected Findings

| # | Location | Vulnerability | CWE | OWASP Top 10 (2021) | ASVS | Severity |
|---|----------|---------------|-----|----------------------|------|----------|
| 1 | `RawProductRepository.LoginRaw` | SQL Injection (auth bypass) | CWE-89 | A03: Injection | V5.3.4 | Critical |
| 2 | `RawProductRepository.Search` | SQL Injection | CWE-89 | A03 | V5.3.4 | Critical |
| 3 | `RawProductRepository.Promote` | SQL Injection | CWE-89 | A03 | V5.3.4 | Critical |
| 4 | `RawProductRepository.FilterByJsonQuery` / `SearchController.FilterJson` | NoSQL/document-query injection (JSONPath analog) | CWE-943 | A03 | V5.3.4 | High |
| 5 | `ProductImportService.ParseProductXml` | XXE | CWE-611 | A05: Security Misconfiguration | V5.5.2 | Critical |
| 6 | `SearchController.FetchSupplierDoc` | SSRF | CWE-918 | A10: SSRF | V12.6 | High |
| 7 | `SearchController.Search` (html format) | Reflected XSS | CWE-79 | A03 | V5.3.3 | High |
| 8 | `ProductController.CreateProduct` / `UpdateProduct` | Mass Assignment / Over-posting | CWE-915 | A08: Software/Data Integrity Failures | V5.1.4 | High |
| 9 | `AuthController` | Hardcoded secrets (JWT key, backdoor admin creds) | CWE-798 | A07: Ident./Auth Failures | V2.10 | Critical |
| 10 | `CryptoService.EncryptLegacy` | Hardcoded DES key + ECB mode | CWE-798, CWE-327 | A02: Cryptographic Failures | V6.2 | Critical |
| 11 | `AdminController.ListUsers` | Missing authorization (no `[Authorize]`) | CWE-862 | A01: Broken Access Control | V4.1 | Critical |
| 12 | `AdminController.Promote` | Privilege escalation | CWE-269 | A01 | V4.1 | Critical |
| 13 | `ProductController.GetProduct` | IDOR (internal CostPrice exposed) | CWE-639 | A01 | V4.2 | High |
| 14 | `ProductController.RedirectToSupplier` | Open Redirect | CWE-601 | A01 | V5.1 | Medium |
| 15 | `Program.cs` (CORS policy) | Wildcard CORS with credentials | CWE-942 | A05 | V14.5 | High |
| 16 | `Program.cs` | Missing security headers (CSP, X-Frame-Options, HSTS) | CWE-693 | A05 | V14.4 | Low/Medium |
| 17 | `Program.cs` | Developer exception page + Swagger UI always enabled | CWE-489, CWE-497 | A05 | V14.3 | Medium |
| 18 | `Program.cs` (`/files` static route) | Unauthenticated directory listing of uploads | CWE-548 | A01 | V12.3 | Medium |
| 19 | `AdminController.DebugConfig` | Sensitive config/secret exposure endpoint | CWE-215, CWE-497 | A05 | V8.3 | Critical |
| 20 | `CryptoService.HashLegacy` | MD5/SHA-1 for integrity hashing | CWE-327, CWE-328 | A02 | V6.2 | High |
| 21 | `CryptoService.GenerateOrderToken` | `System.Random` for security-relevant token | CWE-338 | A02 | V6.3 | Medium |
| 22 | `ApplicationUser` / `SeedData` | Plaintext password storage | CWE-256 | A02 | V2.4 | Critical |
| 23 | `AuthController` | Sensitive data (password, JWT) in logs | CWE-532 | A09: Logging Failures | V7.1 | Medium |
| 24 | `AuthController.Register` | Missing password policy | CWE-521 | A07 | V2.1 | Medium |
| 25 | `InvoiceUploadController.UploadInvoice` | Unrestricted file upload / path traversal | CWE-434, CWE-22 | A05 | V12.1, V12.4 | Critical |

## SCA — Expected Findings

| Dependency | Version pinned | Known issue class | Reachability |
|---|---|---|---|
| `Newtonsoft.Json` | 12.0.1 | Historical high-severity deserialization advisories | Reachable (`RawProductRepository`, `SearchController`) |
| `System.IdentityModel.Tokens.Jwt` | 6.10.0 | Older JWT handling line, historical advisories | Reachable (`AuthController`) |
| `Microsoft.EntityFrameworkCore.Sqlite` / `.Design` | 6.0.0 | Older EF Core line | Reachable (core data access) |
| `Swashbuckle.AspNetCore` | 6.2.3 | Reachable, always-on Swagger amplifies CWE-497 exposure above | Reachable |
| `Microsoft.Data.OData` | 5.8.4 | EOL package, historical advisories | **Unused vulnerable dependency** — never referenced in source; reachability = none |

### Typosquatting / malware-name test set
Following the pattern from the Go+Gin repo (`testdata/typosquat-check/`):
recommend an isolated test-only project referencing fictional look-alike
NuGet package IDs (e.g. `Newtonsoft.Jsonn`, `Swashbuckle.AspNetCoree`),
excluded from the solution's real build/restore path. *(Not yet added to
this seed version — flag if you want it included, following the same
isolation approach as the Go repo.)*

## Secret Detection — Expected Findings
All in `appsettings.Example.json`, duplicated inline in `AuthController` /
`CryptoService` for source-code secret-scanning coverage. **All fake.**
- AWS / Azure / GCP credentials
- GitHub PAT / GitLab Token
- Stripe Secret Key / Slack Token / OpenAI API Key / Twilio Auth Token
- OAuth Client Secret / generic Bearer Token
- Fake RSA private key block / fake SSH private key block
- Hardcoded JWT secret (`SuperSecretJWT`)
- Hardcoded DB password (`Password123`)
- Hardcoded DES key (`8charKey`)
- Hardcoded admin backdoor credentials (`admin` / `admin123`) in `AuthController`
- Hardcoded seed credentials in `SeedData.cs`

## Cryptography Rule Test Coverage
- MD5 / SHA-1: `CryptoService.HashLegacy`
- DES + ECB mode: `CryptoService.EncryptLegacy`
- Weak PRNG: `CryptoService.GenerateOrderToken` (`System.Random`)
- Hardcoded key: `AuthController`, `CryptoService`, `appsettings.Example.json`

## SBOM Notes
- Recommended: CycloneDX `dotnet-CycloneDX` global tool during POC to emit a
  CycloneDX SBOM from `InventoryVuln.csproj`. Not wired into this seed version.
- Expect the SBOM to surface all `PackageReference` entries above plus their
  transitive NuGet graph.

## License Detection
| Dependency | License |
|---|---|
| Microsoft.EntityFrameworkCore.Sqlite / .Design | MIT |
| Newtonsoft.Json | MIT |
| System.IdentityModel.Tokens.Jwt | MIT |
| Swashbuckle.AspNetCore | MIT |
| Microsoft.Data.OData | MS-PL |

Mostly MIT with one MS-PL entry (`Microsoft.Data.OData`) for license-policy
engines to differentiate. Add an LGPL/GPL NuGet package in the expanded
version if copyleft-detection testing needs stronger coverage.

## Relationship to the ASP.NET MVC Repo
This repo intentionally avoids duplicating the ASP.NET MVC repo's
BinaryFormatter/XmlDocument-XXE findings verbatim — here XXE lives in
`ProductImportService` and the injection-class roster is extended with
**Mass Assignment (CWE-915)** and a **NoSQL/JSONPath injection (CWE-943)**
analog, both distinctive to a pure Web API's model-binding and
document-query patterns rather than an MVC view-rendering app.
