using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Input;
using PowerScap.Engine.Cache;
using PowerScap.Engine.Ncp;
using PowerScap.Engine.Profile;

namespace PowerScap.Gui
{
    /// <summary>The window: side-rail navigation, elevation state and the five screens.</summary>
    public class MainViewModel : ObservableObject
    {
        string page = "System";
        string status;

        public MainViewModel(GuiSettings settings, string settingsPath, IHttpTransport http, string launcherScript)
        {
            Settings = settings;
            SettingsPath = settingsPath;
            Http = http ?? new HttpTransport();
            LauncherScript = launcherScript;
            IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

            System = new SystemViewModel(this);
            Content = new ContentViewModel(this);
            Scan = new ScanViewModel(this);
            Results = new ResultsViewModel(this);
            Options = new SettingsViewModel(this);

            NavigateCommand = new RelayCommand(p => Page = Convert.ToString(p));
            RestartElevatedCommand = new RelayCommand(RestartElevated, () => !IsElevated && !string.IsNullOrEmpty(LauncherScript) && !Scan.IsRunning);
        }

        public GuiSettings Settings { get; private set; }
        public string SettingsPath { get; private set; }
        public IHttpTransport Http { get; private set; }
        public string LauncherScript { get; private set; }
        public bool IsElevated { get; private set; }
        public string ElevationText { get { return IsElevated ? "Running as administrator" : "Not elevated"; } }

        public SystemViewModel System { get; private set; }
        public ContentViewModel Content { get; private set; }
        public ScanViewModel Scan { get; private set; }
        public ResultsViewModel Results { get; private set; }
        public SettingsViewModel Options { get; private set; }

        public ICommand NavigateCommand { get; private set; }
        public ICommand RestartElevatedCommand { get; private set; }

        /// <summary>Raised when the window should close (a restart as administrator was started).</summary>
        public event EventHandler CloseRequested;

        public string Page
        {
            get { return page; }
            set
            {
                if (!Set(ref page, value)) return;
                Raise("IsSystemPage"); Raise("IsContentPage"); Raise("IsScanPage"); Raise("IsResultsPage"); Raise("IsSettingsPage");
                if (value == "Results") Results.EnsureLoaded();
            }
        }

        public bool IsSystemPage { get { return page == "System"; } }
        public bool IsContentPage { get { return page == "Content"; } }
        public bool IsScanPage { get { return page == "Scan"; } }
        public bool IsResultsPage { get { return page == "Results"; } }
        public bool IsSettingsPage { get { return page == "Settings"; } }

        /// <summary>One-line status at the bottom of the window (latest event or error).</summary>
        public string Status
        {
            get { return status; }
            set { Set(ref status, value); }
        }

        public ContentCache OpenCache() { return new ContentCache(Settings.EffectiveCacheRoot, Http); }
        public NcpClient OpenNcp() { return new NcpClient(Http); }

        public void SaveSettings()
        {
            try { Settings.Save(SettingsPath); }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
                Status = "Settings could not be saved: " + e.Message;
            }
        }

        /// <summary>Called once the window is shown: profile the machine, list the cache, optionally check for updates.</summary>
        public void Start()
        {
            System.Refresh();
            Content.Reload();
            if (Settings.CheckUpdatesOnLaunch) Content.CheckUpdates();
        }

        internal void OnProfileLoaded(SystemProfile profile)
        {
            Content.ApplyProfile(profile);
        }

        void RestartElevated()
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
                Arguments = "-NoProfile -STA -WindowStyle Hidden -File \"" + LauncherScript + "\"",
                Verb = "runas",
                UseShellExecute = true
            };
            try
            {
                Process.Start(psi);
                var h = CloseRequested;
                if (h != null) h(this, EventArgs.Empty);
            }
            catch (Win32Exception)
            {
                Status = "Restart as administrator was cancelled.";
            }
        }
    }
}
