using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using PowerScap.Engine.Cache;
using PowerScap.Engine.Content;
using PowerScap.Engine.Ncp;
using PowerScap.Engine.Profile;
using PowerScap.Engine.Scan;

namespace PowerScap.Gui
{
    public class ProfileOption
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public override string ToString() { return Title; }
    }

    /// <summary>A cached benchmark (newest version of each checklist) as the Content list shows it.</summary>
    public class BenchmarkItem : ObservableObject
    {
        bool selected, detected, updateAvailable, profilesLoading = true;
        string updateText, profileError;
        ProfileOption profile;

        public BenchmarkItem(CacheEntry entry, string path)
        {
            Entry = entry;
            Path = path;
            Profiles = new ObservableCollection<ProfileOption>();
        }

        public CacheEntry Entry { get; private set; }
        public string Path { get; private set; }
        public string Title { get { return Entry.ChecklistName ?? Entry.BenchmarkTitle ?? Entry.FileName; } }
        public string Version { get { return Entry.BenchmarkVersion; } }
        public string Source { get { return Entry.Imported ? "Imported " + Entry.FileName : Entry.ResourceType; } }
        public string Added { get { return Entry.AddedUtc.ToLocalTime().ToString("yyyy-MM-dd"); } }
        public bool Missing { get { return Entry.Missing; } }

        public bool SignatureInvalid { get { return Entry.Signature != null && Entry.Signature.State == SignatureState.Invalid; } }

        public string SignatureText
        {
            get
            {
                var s = Entry.Signature;
                if (s == null) return "Unknown";
                if (s.State == SignatureState.Valid) return s.ChainTrusted ? "Signed" : "Signed (untrusted issuer)";
                return s.State == SignatureState.Invalid ? "INVALID signature" : "Unsigned";
            }
        }

        /// <summary>Scannable: on disk, signature not invalid and profiles read.</summary>
        public bool CanScan { get { return !Missing && !SignatureInvalid && profileError == null; } }

        public bool IsSelected
        {
            get { return selected; }
            set { if (Set(ref selected, value && CanScan)) { var h = SelectionChanged; if (h != null) h(this, EventArgs.Empty); } }
        }

        public event EventHandler SelectionChanged;

        public bool Detected
        {
            get { return detected; }
            set { Set(ref detected, value); }
        }

        public bool UpdateAvailable
        {
            get { return updateAvailable; }
            set { Set(ref updateAvailable, value); }
        }

        public string UpdateText
        {
            get { return updateText; }
            set { Set(ref updateText, value); }
        }

        public ObservableCollection<ProfileOption> Profiles { get; private set; }

        public ProfileOption Profile
        {
            get { return profile; }
            set { if (Set(ref profile, value)) { var h = ProfileChanged; if (h != null) h(this, EventArgs.Empty); } }
        }

        public event EventHandler ProfileChanged;

        public bool ProfilesLoading
        {
            get { return profilesLoading; }
            set { Set(ref profilesLoading, value); }
        }

        public string ProfileError
        {
            get { return profileError; }
            set { Set(ref profileError, value); Raise("CanScan"); }
        }
    }

    /// <summary>A checklist from the NIST NCP catalog with SCAP content for Windows.</summary>
    public class CatalogItem : ObservableObject
    {
        string state;
        bool busy;

        public NcpChecklist Checklist { get; set; }
        public NcpResource Resource { get; set; }
        public bool Detected { get; set; }
        /// <summary>The checklist's name, with the part this benchmark covers when the checklist has several.</summary>
        public string Name
        {
            get
            {
                string part = NcpClient.PartName(Checklist, Resource);
                return part == null ? Checklist.Name : Checklist.Name + " - " + part;
            }
        }
        public string Version { get { return Checklist.Version; } }
        public string ResourceType { get { return Resource.TypeName; } }
        public string Updated { get { return Checklist.LastModified == DateTime.MinValue ? "" : Checklist.LastModified.ToString("yyyy-MM-dd"); } }

        /// <summary>"In cache", "Downloading...", an error, or empty.</summary>
        public string State
        {
            get { return state; }
            set { Set(ref state, value); }
        }

        public bool IsBusy
        {
            get { return busy; }
            set { Set(ref busy, value); }
        }
    }

    /// <summary>Step 2: cached benchmarks to scan (with profile, detected and update badges), NCP search and import.</summary>
    public class ContentViewModel : ObservableObject
    {
        readonly MainViewModel main;
        SystemProfile profile;
        IList<UpdateInfo> updates = new List<UpdateInfo>();
        string searchText = "", catalogMessage, cacheMessage;
        bool searching, checking;
        int loadGeneration;

        public ContentViewModel(MainViewModel main)
        {
            this.main = main;
            Items = new ObservableCollection<BenchmarkItem>();
            Catalog = new ObservableCollection<CatalogItem>();
            ReloadCommand = new RelayCommand(Reload);
            CheckUpdatesCommand = new RelayCommand(CheckUpdates, () => !IsChecking);
            SearchCommand = new RelayCommand(() => Search(false), () => !IsSearching);
            FindForSystemCommand = new RelayCommand(() => Search(true), () => !IsSearching);
            DownloadCommand = new RelayCommand(p => Download(p as CatalogItem), p => p is CatalogItem && !((CatalogItem)p).IsBusy);
            DownloadUpdateCommand = new RelayCommand(p => DownloadUpdate(p as BenchmarkItem), p => p is BenchmarkItem && ((BenchmarkItem)p).UpdateAvailable);
            ImportCommand = new RelayCommand(Import);
            SelectDetectedCommand = new RelayCommand(() => { foreach (var i in Items) i.IsSelected = i.Detected; });
            ScanSelectedCommand = new RelayCommand(() => main.Scan.Start(Items.Where(i => i.IsSelected).ToList()),
                () => SelectedCount > 0 && !main.Scan.IsRunning);
        }

        public ObservableCollection<BenchmarkItem> Items { get; private set; }
        public ObservableCollection<CatalogItem> Catalog { get; private set; }

        public ICommand ReloadCommand { get; private set; }
        public ICommand CheckUpdatesCommand { get; private set; }
        public ICommand SearchCommand { get; private set; }
        public ICommand FindForSystemCommand { get; private set; }
        public ICommand DownloadCommand { get; private set; }
        public ICommand DownloadUpdateCommand { get; private set; }
        public ICommand ImportCommand { get; private set; }
        public ICommand SelectDetectedCommand { get; private set; }
        public ICommand ScanSelectedCommand { get; private set; }

        public int SelectedCount { get { return Items.Count(i => i.IsSelected); } }
        public string ScanButtonText { get { int n = SelectedCount; return n == 0 ? "Select benchmarks to scan" : "Scan " + n + (n == 1 ? " benchmark" : " benchmarks"); } }

        public string SearchText
        {
            get { return searchText; }
            set { Set(ref searchText, value ?? ""); }
        }

        public bool IsSearching
        {
            get { return searching; }
            private set { Set(ref searching, value); }
        }

        public bool IsChecking
        {
            get { return checking; }
            private set { Set(ref checking, value); }
        }

        public string CatalogMessage
        {
            get { return catalogMessage; }
            private set { Set(ref catalogMessage, value); }
        }

        public string CacheMessage
        {
            get { return cacheMessage; }
            private set { Set(ref cacheMessage, value); }
        }

        /// <summary>Lists the cache (newest version per checklist) and reads each benchmark's profiles in the background.</summary>
        public void Reload()
        {
            IList<CacheEntry> entries;
            ContentCache cache;
            try
            {
                cache = main.OpenCache();
                entries = cache.List();
            }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
                CacheMessage = "The content cache could not be read: " + e.Message;
                return;
            }
            var selected = new HashSet<string>(Items.Where(i => i.IsSelected).Select(i => i.Entry.Id));
            Items.Clear();
            var latest = entries
                .GroupBy(e => e.ChecklistId.HasValue ? "c" + e.ChecklistId.Value + "|" + (NcpClient.Series(e.FileName) ?? e.BenchmarkId) : "b" + e.BenchmarkId)
                .Select(g => g.OrderByDescending(e => e.AddedUtc).First())
                .OrderBy(e => e.ChecklistName ?? e.BenchmarkTitle, StringComparer.OrdinalIgnoreCase);
            foreach (var e in latest)
            {
                var item = new BenchmarkItem(e, cache.PathOf(e));
                item.SelectionChanged += (s, a) => { Raise("SelectedCount"); Raise("ScanButtonText"); };
                item.ProfileChanged += OnProfileChanged;
                Items.Add(item);
            }
            CacheMessage = Items.Count == 0 ? "No content cached yet. Search the NIST catalog below, or import a SCAP zip." : null;
            ApplyProfile(profile);
            ApplyUpdates();
            LoadProfiles(selected);
            Raise("SelectedCount");
            Raise("ScanButtonText");
        }

        /// <summary>One benchmark at a time: a large data stream holds hundreds of MB while it is parsed.</summary>
        void LoadProfiles(HashSet<string> reselect)
        {
            int generation = ++loadGeneration;
            var ui = Background.UiContext();
            var work = Items.ToList();
            foreach (var it in work.Where(i => i.Missing))
            {
                it.ProfilesLoading = false;
                it.ProfileError = "The content file is missing from the cache.";
            }
            System.Threading.Tasks.Task.Factory.StartNew(() =>
            {
                foreach (var item in work.Where(i => !i.Missing))
                {
                    if (generation != loadGeneration) return;
                    var it = item;
                    IList<KeyValuePair<string, string>> list = null;
                    string error = null;
                    try { list = ScanRunner.Profiles(ScapContentLoader.Load(it.Path)); }
                    catch (Exception e)
                    {
                        if (e is OutOfMemoryException) throw;
                        error = "Could not read this content: " + Background.Describe(e);
                    }
                    ui.Post(_ =>
                    {
                        if (generation != loadGeneration) return;
                        if (error != null) { it.ProfilesLoading = false; it.ProfileError = error; return; }
                        foreach (var p in list) it.Profiles.Add(new ProfileOption { Id = p.Key, Title = p.Value });
                        string chosen;
                        main.Settings.ProfileChoices.TryGetValue(it.Entry.BenchmarkId ?? "", out chosen);
                        it.Profile = it.Profiles.FirstOrDefault(p => p.Id == chosen) ?? it.Profiles.FirstOrDefault();
                        it.ProfilesLoading = false;
                        if (reselect.Contains(it.Entry.Id)) it.IsSelected = true;
                    }, null);
                }
            }, System.Threading.Tasks.TaskCreationOptions.LongRunning);
        }

        void OnProfileChanged(object sender, EventArgs e)
        {
            var it = (BenchmarkItem)sender;
            if (it.Profile == null || string.IsNullOrEmpty(it.Entry.BenchmarkId) || it.ProfilesLoading) return;
            main.Settings.ProfileChoices[it.Entry.BenchmarkId] = it.Profile.Id;
            main.SaveSettings();
        }

        /// <summary>Marks the benchmarks for products detected on this machine.</summary>
        public void ApplyProfile(SystemProfile p)
        {
            profile = p;
            if (p == null) return;
            foreach (var i in Items) i.Detected = IsForThisMachine(p, i.Entry.Targets, i.Entry.ChecklistName ?? i.Entry.BenchmarkTitle);
            foreach (var c in Catalog) c.Detected = BenchmarkMatcher.ProductFor(p, c.Checklist.Targets) != null;
        }

        /// <summary>NCP targets when the cache recorded them; otherwise the title names a detected product.</summary>
        public static bool IsForThisMachine(SystemProfile p, IList<string> targets, string title)
        {
            if (targets != null && targets.Count > 0) return BenchmarkMatcher.ProductFor(p, targets) != null;
            if (string.IsNullOrEmpty(title)) return false;
            string t = title.ToLowerInvariant();
            return p.Products.Any(x => new[] { x.NcpTarget, x.Name }.Any(n =>
            {
                string name = (n ?? "").ToLowerInvariant();
                if (name.StartsWith("microsoft ")) name = name.Substring(10);
                return name.Length > 3 && t.Contains(name);
            }));
        }

        public void CheckUpdates()
        {
            if (IsChecking) return;
            IsChecking = true;
            var cache = main.OpenCache();
            var checker = new UpdateChecker(main.OpenNcp(), main.Http);
            Background.Run(() => checker.Check(cache.List()), result =>
            {
                IsChecking = false;
                updates = result;
                ApplyUpdates();
                int n = result.Count(u => u.State == UpdateState.UpdateAvailable);
                bool failed = result.Any(u => u.State == UpdateState.CheckFailed);
                main.Status = failed ? "Update check failed (offline?). Cached content still works."
                    : n == 0 ? "Cached content is up to date." : n + (n == 1 ? " update is" : " updates are") + " available.";
            }, e =>
            {
                IsChecking = false;
                main.Status = "Update check failed: " + Background.Describe(e);
            });
        }

        void ApplyUpdates()
        {
            foreach (var i in Items)
            {
                var u = updates.FirstOrDefault(x => x.Cached != null && x.Cached.Id == i.Entry.Id);
                i.UpdateAvailable = u != null && u.State == UpdateState.UpdateAvailable;
                i.UpdateText = u == null ? null
                    : u.State == UpdateState.UpdateAvailable ? "Update available"
                    : u.State == UpdateState.Current ? "Current"
                    : u.State == UpdateState.CheckFailed ? "Check failed" : "Not in catalog";
                if (u != null && u.Checklist != null && profile != null && (i.Entry.Targets == null || i.Entry.Targets.Count == 0))
                    i.Detected = BenchmarkMatcher.ProductFor(profile, u.Checklist.Targets) != null;
            }
        }

        void Search(bool forThisSystem)
        {
            if (IsSearching) return;
            IsSearching = true;
            CatalogMessage = forThisSystem ? "Finding benchmarks for this machine..." : "Searching the NIST National Checklist Program...";
            var ncp = main.OpenNcp();
            string keyword = forThisSystem ? "" : SearchText.Trim();
            string flavor = main.Settings.Flavor;
            var p = profile;
            Background.Run(() =>
            {
                var catalog = ncp.Search(keyword, new[] { NcpClient.Scap14, NcpClient.Scap13, NcpClient.Scap12 });
                IEnumerable<NcpChecklist> list = catalog;
                if (forThisSystem)
                {
                    var sp = p ?? SystemProfile.Collect();
                    list = BenchmarkMatcher.Match(sp, catalog).Select(m => m.Checklist);
                }
                // One row per benchmark: a checklist can hold several (IIS Server and Site).
                return list.SelectMany(c => NcpClient.PickScapResources(c, flavor).Select(r => new CatalogItem { Checklist = c, Resource = r }))
                    .GroupBy(c => c.Resource.Location).Select(g => g.First()).ToList();
            }, list =>
            {
                IsSearching = false;
                Catalog.Clear();
                var cachedFiles = new HashSet<string>(Items.Select(i => i.Entry.FileName ?? ""), StringComparer.OrdinalIgnoreCase);
                foreach (var c in list.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                {
                    if (cachedFiles.Contains(c.Resource.FileName ?? "")) c.State = "In cache";
                    Catalog.Add(c);
                }
                ApplyProfile(profile);
                CatalogMessage = list.Count == 0 ? "No checklists with Windows SCAP content matched." : list.Count + " checklists with SCAP content.";
            }, e =>
            {
                IsSearching = false;
                CatalogMessage = "Search failed: " + Background.Describe(e);
            });
        }

        void Download(CatalogItem c)
        {
            if (c == null || c.IsBusy) return;
            c.IsBusy = true;
            c.State = "Downloading...";
            var cache = main.OpenCache();
            Background.Run(() => cache.Download(c.Checklist, c.Resource), entry =>
            {
                c.IsBusy = false;
                c.State = "In cache";
                main.Status = "Downloaded " + c.Name + ".";
                Reload();
            }, e =>
            {
                c.IsBusy = false;
                c.State = "Failed";
                main.Status = "Could not download " + c.Name + ": " + Background.Describe(e);
            });
        }

        void DownloadUpdate(BenchmarkItem item)
        {
            var u = updates.FirstOrDefault(x => x.Cached != null && x.Cached.Id == item.Entry.Id);
            if (u == null || u.Checklist == null) return;
            var resource = NcpClient.PickScapResource(u.Checklist, main.Settings.Flavor, item.Entry.FileName) ?? u.Latest;
            item.UpdateText = "Downloading...";
            item.UpdateAvailable = false;
            var cache = main.OpenCache();
            Background.Run(() => cache.Download(u.Checklist, resource), entry =>
            {
                updates = updates.Where(x => x != u).ToList();
                main.Status = "Updated " + item.Title + " to " + entry.BenchmarkVersion + ". The older version stays in the cache.";
                Reload();
            }, e =>
            {
                item.UpdateText = "Download failed";
                item.UpdateAvailable = true;
                main.Status = "Could not download the update for " + item.Title + ": " + Background.Describe(e);
            });
        }

        void Import()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import SCAP content",
                Filter = "SCAP content (*.zip;*.xml)|*.zip;*.xml|All files (*.*)|*.*",
                Multiselect = true
            };
            // An installed SCC carries content NCP does not list (NIWC's Windows Updates benchmark): start there.
            var scc = SccContent.Folders().FirstOrDefault();
            if (scc != null) dlg.InitialDirectory = scc;
            if (dlg.ShowDialog() != true) return;
            var files = dlg.FileNames;
            var cache = main.OpenCache();
            main.Status = "Importing...";
            Background.Run(() =>
            {
                var errors = new List<string>();
                foreach (var f in files)
                {
                    try { cache.Import(f); }
                    catch (Exception e)
                    {
                        if (e is OutOfMemoryException) throw;
                        errors.Add(System.IO.Path.GetFileName(f) + ": " + Background.Describe(e));
                    }
                }
                return errors;
            }, errors =>
            {
                main.Status = errors.Count == 0 ? "Imported " + files.Length + (files.Length == 1 ? " file." : " files.") : "Import failed. " + string.Join("; ", errors);
                Reload();
            }, e => main.Status = "Import failed: " + Background.Describe(e));
        }
    }
}
