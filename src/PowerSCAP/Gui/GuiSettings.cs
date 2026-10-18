using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Markup;
using Microsoft.Win32;
using PowerScap.Engine.Cache;
using PowerScap.Engine.Scan;

namespace PowerScap.Gui
{
    /// <summary>The person's GUI choices, kept in %LOCALAPPDATA%\PowerSCAP\settings.json (%POWERSCAP_SETTINGS% overrides the path).</summary>
    public class GuiSettings
    {
        public GuiSettings()
        {
            Theme = "Dark";
            Flavor = "SCAP 1.4 Content";
            CheckUpdatesOnLaunch = true;
            Html = true;
            Cklb = true;
            ProfileChoices = new Dictionary<string, string>(StringComparer.Ordinal);
        }

        /// <summary>Dark, Light or System (follow Windows).</summary>
        public string Theme { get; set; }
        public string CacheRoot { get; set; }
        public string OutputPath { get; set; }
        public bool CheckUpdatesOnLaunch { get; set; }
        /// <summary>The NCP resource type downloads prefer: "SCAP 1.4 Content" or "SCAP 1.3 Content".</summary>
        public string Flavor { get; set; }
        public bool Html { get; set; }
        public bool Cklb { get; set; }
        public bool Oval { get; set; }
        public bool Arf { get; set; }
        /// <summary>Lets scans run without administrator rights (checks that need elevation report errors).</summary>
        public bool AllowUnelevated { get; set; }
        /// <summary>The profile chosen per benchmark id.</summary>
        public Dictionary<string, string> ProfileChoices { get; set; }

        public string EffectiveCacheRoot { get { return string.IsNullOrEmpty(CacheRoot) ? ContentCache.DefaultRoot() : CacheRoot; } }

        public string EffectiveOutputPath
        {
            get
            {
                return string.IsNullOrEmpty(OutputPath)
                    ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PowerSCAP Results")
                    : OutputPath;
            }
        }

        public OutputFormats Formats
        {
            get
            {
                var f = OutputFormats.None;
                if (Html) f |= OutputFormats.Html;
                if (Cklb) f |= OutputFormats.Cklb;
                if (Oval) f |= OutputFormats.Oval;
                if (Arf) f |= OutputFormats.Arf;
                return f;
            }
        }

        public static string DefaultPath()
        {
            string env = Environment.GetEnvironmentVariable("POWERSCAP_SETTINGS");
            if (!string.IsNullOrEmpty(env)) return env;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"PowerSCAP\settings.json");
        }

        /// <summary>Defaults when the file is missing or unreadable.</summary>
        public static GuiSettings Load(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    var s = new JavaScriptSerializer().Deserialize<GuiSettings>(File.ReadAllText(path, Encoding.UTF8));
                    if (s != null)
                    {
                        if (s.ProfileChoices == null) s.ProfileChoices = new Dictionary<string, string>(StringComparer.Ordinal);
                        if (string.IsNullOrEmpty(s.Theme)) s.Theme = "Dark";
                        if (string.IsNullOrEmpty(s.Flavor)) s.Flavor = "SCAP 1.4 Content";
                        return s;
                    }
                }
            }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
            }
            return new GuiSettings();
        }

        public void Save(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
            File.WriteAllText(path, new JavaScriptSerializer().Serialize(this), Encoding.UTF8);
        }
    }

    /// <summary>Swaps the Dark/Light brush dictionaries; controls use DynamicResource so the change applies live.</summary>
    public static class ThemeManager
    {
        public static string ThemeDirectory { get; set; }

        /// <summary>Dark or Light; System reads Windows' app theme (AppsUseLightTheme).</summary>
        public static string Resolve(string theme)
        {
            if (string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase)) return "Light";
            if (string.Equals(theme, "System", StringComparison.OrdinalIgnoreCase)) return WindowsUsesLightTheme() ? "Light" : "Dark";
            return "Dark";
        }

        public static bool WindowsUsesLightTheme()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    object v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    return v is int && (int)v != 0;
                }
            }
            catch (System.Security.SecurityException) { return false; }
        }

        public static ResourceDictionary LoadDictionary(string file)
        {
            using (var s = File.OpenRead(file))
                return (ResourceDictionary)XamlReader.Load(s);
        }

        /// <summary>Loads the controls dictionary once, then the chosen theme's brushes in front of it.</summary>
        public static void Apply(Application app, string theme)
        {
            string resolved = Resolve(theme);
            var merged = app.Resources.MergedDictionaries;
            var brushes = LoadDictionary(Path.Combine(ThemeDirectory, resolved + ".xaml"));
            brushes["ThemeName"] = resolved;
            if (merged.Count == 0)
            {
                merged.Add(brushes);
                merged.Add(LoadDictionary(Path.Combine(ThemeDirectory, "Controls.xaml")));
            }
            else merged[0] = brushes;
            foreach (Window w in app.Windows) ApplyTitleBar(w, resolved == "Dark");
        }

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

        /// <summary>Dark or light window title bar (Windows 10 20H1 and later; ignored elsewhere).</summary>
        public static void ApplyTitleBar(Window w, bool dark)
        {
            var hwnd = new WindowInteropHelper(w).Handle;
            if (hwnd == IntPtr.Zero) return;
            int on = dark ? 1 : 0;
            try { DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)); }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }
    }
}
