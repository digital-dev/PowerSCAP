using System;
using System.Globalization;
using System.IO;
using System.Net;

namespace PowerScap.Engine.Ncp
{
    public class HttpHead
    {
        public int Status { get; set; }
        public string ETag { get; set; }
        public DateTime? LastModified { get; set; }
        public long? Length { get; set; }
    }

    /// <summary>All network access PowerSCAP does. Tests substitute a fake.</summary>
    public interface IHttpTransport
    {
        string GetString(string url);
        HttpHead Head(string url);
        void Download(string url, string destinationPath);
    }

    /// <summary>A failed request: unreachable host, timeout, non-success status or unusable response.</summary>
    public class NcpException : Exception
    {
        public string Url { get; private set; }

        public NcpException(string url, string message) : this(url, message, null) { }

        public NcpException(string url, string message, Exception inner) : base(message + " (" + url + ")", inner)
        {
            Url = url;
        }
    }

    /// <summary>HTTPS over HttpWebRequest with TLS 1.2, a 60 s timeout and a PowerSCAP user agent.</summary>
    public class HttpTransport : IHttpTransport
    {
        public int TimeoutMs { get; set; }

        public HttpTransport()
        {
            TimeoutMs = 60000;
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        }

        HttpWebRequest Create(string url, string method)
        {
            var r = (HttpWebRequest)WebRequest.Create(url);
            r.Method = method;
            r.Timeout = TimeoutMs;
            r.ReadWriteTimeout = TimeoutMs;
            r.UserAgent = "PowerSCAP/" + EngineInfo.Version;
            r.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            return r;
        }

        HttpWebResponse Send(HttpWebRequest r, string url)
        {
            try
            {
                return (HttpWebResponse)r.GetResponse();
            }
            catch (WebException ex)
            {
                var resp = ex.Response as HttpWebResponse;
                string what = resp != null ? "HTTP " + (int)resp.StatusCode + " " + resp.StatusDescription : ex.Message;
                if (resp != null) resp.Close();
                throw new NcpException(url, what, ex);
            }
        }

        public string GetString(string url)
        {
            using (var resp = Send(Create(url, "GET"), url))
            using (var reader = new StreamReader(resp.GetResponseStream()))
            {
                try { return reader.ReadToEnd(); }
                catch (IOException ex) { throw new NcpException(url, ex.Message, ex); }
            }
        }

        public HttpHead Head(string url)
        {
            using (var resp = Send(Create(url, "HEAD"), url))
            {
                var h = new HttpHead { Status = (int)resp.StatusCode, ETag = resp.Headers[HttpResponseHeader.ETag] };
                DateTime lm;
                string lmText = resp.Headers[HttpResponseHeader.LastModified];
                if (lmText != null && DateTime.TryParse(lmText, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out lm)) h.LastModified = lm;
                if (resp.ContentLength >= 0) h.Length = resp.ContentLength;
                return h;
            }
        }

        public void Download(string url, string destinationPath)
        {
            using (var resp = Send(Create(url, "GET"), url))
            using (var input = resp.GetResponseStream())
            using (var output = File.Create(destinationPath))
            {
                try { input.CopyTo(output); }
                catch (IOException ex) { throw new NcpException(url, ex.Message, ex); }
                catch (WebException ex) { throw new NcpException(url, ex.Message, ex); }
            }
        }
    }
}
