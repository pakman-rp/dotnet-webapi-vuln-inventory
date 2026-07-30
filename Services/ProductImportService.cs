using System.Xml;

namespace InventoryVuln.Services;

public class ProductImportService
{
    /// <summary>
    /// ParseProductXml — VULN (CWE-611): XXE. XmlDocument is configured with
    /// an XmlUrlResolver and DTD processing left enabled, so a crafted
    /// DOCTYPE/ENTITY declaration can read local files or trigger SSRF
    /// against internal services (e.g. cloud metadata endpoints).
    /// </summary>
    public XmlDocument ParseProductXml(string xml)
    {
        var doc = new XmlDocument
        {
            XmlResolver = new XmlUrlResolver() // VULN: reintroduces external entity resolution
        };
        doc.LoadXml(xml); // VULN sink
        return doc;
    }
}
