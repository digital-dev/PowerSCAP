using System.Windows;
using System.Windows.Input;

namespace PowerScap.Gui
{
    /// <summary>Settings: every change is saved immediately; the theme applies live.</summary>
    public class SettingsViewModel : ObservableObject
    {
        readonly MainViewModel main;

        public SettingsViewModel(MainViewModel main)
        {
            this.main = main;
            BrowseOutputCommand = new RelayCommand(() => { var f = PickFolder(OutputPath); if (f != null) OutputPath = f; });
            BrowseCacheCommand = new RelayCommand(() => { var f = PickFolder(CacheRoot); if (f != null) CacheRoot = f; }, () => !main.Scan.IsRunning);
            OpenCacheCommand = new RelayCommand(() => Shell.OpenFolder(CacheRoot));
        }

        GuiSettings S { get { return main.Settings; } }

        public ICommand BrowseOutputCommand { get; private set; }
        public ICommand BrowseCacheCommand { get; private set; }
        public ICommand OpenCacheCommand { get; private set; }

        public string Theme
        {
            get { return S.Theme; }
            set
            {
                if (value == null || value == S.Theme) return;
                S.Theme = value;
                Save("Theme");
                if (Application.Current != null) ThemeManager.Apply(Application.Current, value);
            }
        }

        public string OutputPath
        {
            get { return S.EffectiveOutputPath; }
            set { S.OutputPath = value; Save("OutputPath"); }
        }

        public string CacheRoot
        {
            get { return S.EffectiveCacheRoot; }
            set
            {
                S.CacheRoot = value;
                Save("CacheRoot");
                main.Content.Reload();
            }
        }

        public bool CheckUpdatesOnLaunch { get { return S.CheckUpdatesOnLaunch; } set { S.CheckUpdatesOnLaunch = value; Save("CheckUpdatesOnLaunch"); } }
        public string Flavor { get { return S.Flavor; } set { if (value != null) { S.Flavor = value; Save("Flavor"); } } }
        public bool Html { get { return S.Html; } set { S.Html = value; Save("Html"); } }
        public bool Cklb { get { return S.Cklb; } set { S.Cklb = value; Save("Cklb"); } }
        public bool Oval { get { return S.Oval; } set { S.Oval = value; Save("Oval"); } }
        public bool Arf { get { return S.Arf; } set { S.Arf = value; Save("Arf"); } }
        public bool AllowUnelevated { get { return S.AllowUnelevated; } set { S.AllowUnelevated = value; Save("AllowUnelevated"); } }

        void Save(string property)
        {
            main.SaveSettings();
            Raise(property);
        }

        static string PickFolder(string start)
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { SelectedPath = start ?? "", ShowNewFolderButton = true })
                return dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK ? dlg.SelectedPath : null;
        }
    }
}
