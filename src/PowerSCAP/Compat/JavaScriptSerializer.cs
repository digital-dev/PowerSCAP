// PowerShell 7 (.NET) only: the module compiles this file instead of referencing System.Web.Extensions, which exists
// only in .NET Framework. It covers the part of JavaScriptSerializer PowerSCAP uses, on System.Text.Json, and keeps
// its JSON: dates as "\/Date(ms)\/", enums as numbers, public fields and properties, names matched without case. Files
// written by Windows PowerShell 5.1 and PowerShell 7 (cache manifest, history, answers, settings) read the same in both.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace System.Web.Script.Serialization
{
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class ScriptIgnoreAttribute : Attribute { }

    public class JavaScriptSerializer
    {
        public JavaScriptSerializer()
        {
            MaxJsonLength = 2097152;
            RecursionLimit = 100;
        }

        /// <summary>Accepted for compatibility; System.Text.Json has no length limit.</summary>
        public int MaxJsonLength { get; set; }
        public int RecursionLimit { get; set; }

        JsonSerializerOptions Options()
        {
            var o = new JsonSerializerOptions
            {
                IncludeFields = true,
                PropertyNameCaseInsensitive = true,
                MaxDepth = Math.Max(RecursionLimit, 64),
                NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
                TypeInfoResolver = new DefaultJsonTypeInfoResolver { Modifiers = { SkipScriptIgnore } }
            };
            o.Converters.Add(new MsDateConverter());
            return o;
        }

        static void SkipScriptIgnore(JsonTypeInfo info)
        {
            if (info.Kind != JsonTypeInfoKind.Object) return;
            for (int i = info.Properties.Count - 1; i >= 0; i--)
            {
                var p = info.Properties[i];
                if (p.AttributeProvider != null && p.AttributeProvider.IsDefined(typeof(ScriptIgnoreAttribute), true)) info.Properties.RemoveAt(i);
            }
        }

        public string Serialize(object obj)
        {
            return JsonSerializer.Serialize(obj, obj == null ? typeof(object) : obj.GetType(), Options());
        }

        public T Deserialize<T>(string input)
        {
            try { return JsonSerializer.Deserialize<T>(input, Options()); }
            catch (JsonException e) { throw new ArgumentException(e.Message, e); }
        }

        /// <summary>Objects as Dictionary&lt;string, object&gt;, arrays as object[], numbers as int, long, decimal or double.</summary>
        public object DeserializeObject(string input)
        {
            try
            {
                using (var doc = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = Math.Max(RecursionLimit, 64), AllowTrailingCommas = true }))
                    return Convert(doc.RootElement);
            }
            catch (JsonException e) { throw new ArgumentException(e.Message, e); }
        }

        static object Convert(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Object:
                    var d = new Dictionary<string, object>();
                    foreach (var p in e.EnumerateObject()) d[p.Name] = Convert(p.Value);
                    return d;
                case JsonValueKind.Array: return e.EnumerateArray().Select(Convert).ToArray();
                case JsonValueKind.String: return e.GetString();
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                case JsonValueKind.Number:
                    int i; long l; decimal m;
                    if (e.TryGetInt32(out i)) return i;
                    if (e.TryGetInt64(out l)) return l;
                    if (e.TryGetDecimal(out m)) return m;
                    return e.GetDouble();
                default: return null;
            }
        }

        /// <summary>JavaScriptSerializer's date: "\/Date(milliseconds since 1970 UTC)\/"; ISO 8601 is read too.</summary>
        sealed class MsDateConverter : JsonConverter<DateTime>
        {
            static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                string s = reader.GetString() ?? "";
                if (s.StartsWith("/Date(", StringComparison.Ordinal))
                {
                    string digits = s.Substring(6, s.IndexOf(')') - 6);
                    int sign = digits.IndexOfAny(new[] { '+', '-' }, 1);
                    if (sign > 0) digits = digits.Substring(0, sign);
                    return Epoch.AddMilliseconds(long.Parse(digits, CultureInfo.InvariantCulture));
                }
                return DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
            }

            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                var utc = value.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(value, DateTimeKind.Local).ToUniversalTime() : value.ToUniversalTime();
                long ms = (long)Math.Floor((utc - Epoch).TotalMilliseconds);
                writer.WriteRawValue("\"\\/Date(" + ms.ToString(CultureInfo.InvariantCulture) + ")\\/\"", true);
            }
        }
    }
}
