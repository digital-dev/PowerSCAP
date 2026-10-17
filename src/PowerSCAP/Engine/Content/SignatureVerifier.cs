using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace PowerScap.Engine.Content
{
    public enum SignatureState { Unsigned, Valid, Invalid }

    public class SignatureReport
    {
        public SignatureState State { get; set; }
        /// <summary>Signing certificate subject.</summary>
        public string Signer { get; set; }
        public string Thumbprint { get; set; }
        public DateTime? NotAfter { get; set; }
        /// <summary>The signer chains to a root this machine trusts (revocation not checked, so this works offline).</summary>
        public bool ChainTrusted { get; set; }
        public string Message { get; set; }

        public override string ToString()
        {
            if (State == SignatureState.Valid) return "Valid, signed by " + Signer + (ChainTrusted ? "" : " (issuer not trusted on this machine)");
            return State + (string.IsNullOrEmpty(Message) ? "" : ": " + Message);
        }
    }

    /// <summary>Verifies the enveloped XML digital signature that signed SCAP data streams carry.</summary>
    public static class SignatureVerifier
    {
        const string C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
        static readonly object registerGate = new object();
        static bool registered;

        /// <summary>
        /// NIWC content canonicalizes with C14N 1.1, which .NET Framework does not implement. It differs from
        /// C14N 1.0 only in xml:id/xml:base inheritance into excluded subsets, which a whole-document enveloped
        /// signature (Reference URI="") never exercises, so C14N 1.0 is registered under the 1.1 URI.
        /// </summary>
        static void Register()
        {
            lock (registerGate)
            {
                if (registered) return;
                CryptoConfig.AddAlgorithm(typeof(XmlDsigC14NTransform), C14N11);
                registered = true;
            }
        }

        /// <summary>Verifies a .zip (every .xml inside must verify) or a single XML file.</summary>
        public static SignatureReport Verify(string contentPath)
        {
            if (contentPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                SignatureReport last = new SignatureReport { State = SignatureState.Unsigned, Message = "No XML in archive." };
                using (var zip = ZipFile.OpenRead(contentPath))
                    foreach (var entry in zip.Entries.Where(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
                        using (var s = entry.Open())
                        {
                            var report = Verify(Load(s));
                            if (report.State == SignatureState.Invalid) return report;
                            if (report.State == SignatureState.Valid || last.State == SignatureState.Unsigned) last = report;
                        }
                return last;
            }
            using (var s = File.OpenRead(contentPath)) return Verify(Load(s));
        }

        static XmlDocument Load(Stream s)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            using (var r = XmlReader.Create(s, settings)) doc.Load(r);
            return doc;
        }

        public static SignatureReport Verify(XmlDocument doc)
        {
            Register();
            var sigs = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
            if (sigs.Count == 0) return new SignatureReport { State = SignatureState.Unsigned };
            if (sigs.Count > 1) return new SignatureReport { State = SignatureState.Invalid, Message = "multiple signatures" };

            var signed = new SignedXml(doc);
            if (!signed.SafeCanonicalizationMethods.Contains(C14N11)) signed.SafeCanonicalizationMethods.Add(C14N11);
            try
            {
                signed.LoadXml((XmlElement)sigs[0]);
            }
            catch (CryptographicException ex)
            {
                return new SignatureReport { State = SignatureState.Invalid, Message = "malformed signature: " + ex.Message };
            }

            X509Certificate2 cert = null;
            foreach (KeyInfoClause clause in signed.KeyInfo)
            {
                var data = clause as KeyInfoX509Data;
                if (data == null || data.Certificates == null) continue;
                cert = data.Certificates.Cast<X509Certificate2>().FirstOrDefault();
                if (cert != null) break;
            }
            if (cert == null) return new SignatureReport { State = SignatureState.Invalid, Message = "no signing certificate in the signature" };

            var report = new SignatureReport { Signer = cert.Subject, Thumbprint = cert.Thumbprint, NotAfter = cert.NotAfter };
            bool ok;
            try { ok = signed.CheckSignature(cert, true); }
            catch (CryptographicException ex) { report.State = SignatureState.Invalid; report.Message = ex.Message; return report; }
            if (!ok)
            {
                report.State = SignatureState.Invalid;
                report.Message = "the content does not match its signature (modified after signing)";
                return report;
            }
            report.State = SignatureState.Valid;
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                report.ChainTrusted = chain.Build(cert);
            }
            return report;
        }
    }
}
