# InventoryVuln — .NET Web API Intentionally Vulnerable Benchmark App

> ⚠️ **DO NOT DEPLOY. DO NOT USE IN PRODUCTION.**
> Intentionally vulnerable benchmark application (OWASP Benchmark / WebGoat
> style) for evaluating SAST/SCA/Secret-scanning tools during commercial
> product POCs. Every vulnerability is intentional and marked with a
> `// VULN:` comment and CWE ID. Every secret is fake.

## Business Scenario
A fictional warehouse/inventory management REST API: products, stock
adjustments, purchase orders, an admin console, a document (invoice) upload
endpoint, and a product search/report API. Pure Web API — no server-rendered
views, distinguishing this repo from the companion ASP.NET MVC repo.

## Stack
- ASP.NET Core Web API (.NET 7), attribute-routed controllers only
- Entity Framework Core + SQLite
- JWT auth (deliberately weak validation)

## Running

```bash
cp appsettings.Example.json appsettings.json
docker compose up --build
```

API available at `http://localhost:8083`. Swagger UI at
`http://localhost:8083/swagger` (deliberately left enabled unconditionally).

## Default (Intentionally Hardcoded) Accounts
| username | password    | role  |
|----------|-------------|-------|
| admin    | admin123    | Admin |
| wclerk   | Password1   | User  |

See `docs/FINDINGS.md` for the full expected SAST/SCA/Secret-detection
results, CWE/OWASP/ASVS mapping, SBOM, and license notes.

## Layout
```
Controllers/   AuthController, ProductController, AdminController,
               InvoiceUploadController, SearchController, StateController
Models/        Product, PurchaseOrder, ApplicationUser (incl. over-posting-prone DTO usage)
Data/          EF Core DbContext + seed data, raw ADO.NET vulnerable queries
Services/      Weak crypto helpers, XML import (XXE)
docs/          Expected findings, CWE/OWASP mapping, SBOM/license notes
.github/workflows/  CI pipeline stub incl. SAST/SCA/secret-scan stages
Jenkinsfile    Jenkins pipeline stub with severity gate
```

## Not Included Yet
Seed version. Planned expansion on request: full CRUD for purchase orders,
background stock-reconciliation job, GraphQL variant, CycloneDX/SPDX SBOM
wired into CI, typosquat fixture (see `docs/FINDINGS.md` note).
