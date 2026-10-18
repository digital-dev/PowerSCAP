using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Windows.Data;
using System.Windows.Input;
using PowerScap.Engine.Reports;

namespace PowerScap.Gui
{
    /// <summary>
    /// A read-only view of a STIG Viewer checklist (.cklb): PowerSCAP's own, or one from SCC or STIG Viewer.
    /// Editing statuses and comments stays with STIG Viewer.
    /// </summary>
    public class ChecklistViewModel : ObservableObject
    {
        public static readonly string[] StatusChoices = { "All", "Open", "Not a Finding", "Not Reviewed", "Not Applicable" };

        readonly MainViewModel main;
        ChecklistFile file;
        ChecklistStig stig;
        ChecklistListing listing;
        bool listed, listingBusy;
        string requested;
        RuleRow selectedRow;
        string statusFilter = "All", catFilter = "All", search = "", message, counts;
        bool loading;
        int loadToken;

        public ChecklistViewModel(MainViewModel main)
        {
            this.main = main;
            Stigs = new ObservableCollection<ChecklistStig>();
            Available = new ObservableCollection<ChecklistListing>();
            Rows = new ObservableCollection<RuleRow>();
            RowsView = CollectionViewSource.GetDefaultView(Rows);
            RowsView.Filter = o => Matches((RuleRow)o);
            OpenCommand = new RelayCommand(Browse, () => !IsLoading);
            ShowFileCommand = new RelayCommand(() => Shell.Select(file.Path), () => file != null);
            ClearFiltersCommand = new RelayCommand(() => { StatusFilter = "All"; CatFilter = "All"; SearchText = ""; });
            Message = "Open a .cklb checklist, or use Checklist (.cklb) on the Results page.";
        }

        public ObservableCollection<ChecklistStig> Stigs { get; private set; }
        /// <summary>Every checklist PowerSCAP knows of: the results folder and each scan in the history, newest first.</summary>
        public ObservableCollection<ChecklistListing> Available { get; private set; }

        /// <summary>Picking a checklist opens it.</summary>
        public ChecklistListing SelectedListing
        {
            get { return listing; }
            set
            {
                if (!Set(ref listing, value) || value == null) return;
                if (file == null || !string.Equals(file.Path, value.Path, StringComparison.OrdinalIgnoreCase)) Load(value.Path);
            }
        }

        /// <summary>Only checklists that hold several STIGs (SCC's or STIG Viewer's can) need the STIG picker.</summary>
        public bool HasManyStigs { get { return Stigs.Count > 1; } }

        public void EnsureListed()
        {
            if (!listed) RefreshList(null);
        }

        /// <summary>Finds the checklists in the results folder and in the scan history (off the UI thread).</summary>
        public void RefreshList(string select)
        {
            if (listingBusy) return;
            listed = true;
            listingBusy = true;
            string folder = main.Settings.EffectiveOutputPath;
            string historyRoot = Engine.Scan.ScanHistory.DefaultRoot();
            string extra = file == null ? null : file.Path;
            Background.Run(() =>
            {
                var files = new System.Collections.Generic.List<string>();
                if (extra != null) files.Add(extra);
                var history = new Engine.Scan.ScanHistory(historyRoot);
                foreach (var e in history.List())
                {
                    string cklb = e.Checklist;
                    if (cklb == null)
                    {
                        // Scans saved before the history recorded checklists: the path is in the saved report.
                        try
                        {
                            var r = history.Load(e.ReportPath);
                            if (r.Files != null && r.Files.ContainsKey("Checklist")) cklb = r.Files["Checklist"];
                        }
                        catch (Exception ex)
                        {
                            if (ex is OutOfMemoryException) throw;
                        }
                    }
                    if (cklb != null) files.Add(cklb);
                }
                return CklbReader.Find(new[] { folder }, files);
            }, found =>
            {
                listingBusy = false;
                Available.Clear();
                foreach (var f in found) Available.Add(f);
                // A checklist already asked for (from Results, Open, or the picker) wins over "newest first".
                string want = select ?? requested;
                var match = want == null ? null : Available.FirstOrDefault(x => string.Equals(x.Path, want, StringComparison.OrdinalIgnoreCase));
                if (match != null) { listing = match; Raise("SelectedListing"); }
                else if (requested == null && Available.Count > 0) SelectedListing = Available[0];
                if (Available.Count == 0 && file == null) Message = "No checklists yet. Scan with the checklist output on, or open a .cklb file.";
            }, e =>
            {
                listingBusy = false;
                main.Status = "Could not list checklists: " + Background.Describe(e);
            });
        }
        public ObservableCollection<RuleRow> Rows { get; private set; }
        public ICollectionView RowsView { get; private set; }
        public ICommand OpenCommand { get; private set; }
        public ICommand ShowFileCommand { get; private set; }
        public ICommand ClearFiltersCommand { get; private set; }

        public string[] Statuses { get { return StatusChoices; } }
        public string[] Cats { get { return ResultsViewModel.CatChoices; } }

        public ChecklistFile File
        {
            get { return file; }
            private set { if (Set(ref file, value)) { Raise("Header"); Raise("HasFile"); } }
        }

        public bool HasFile { get { return file != null; } }

        public string Header
        {
            get
            {
                if (file == null) return null;
                string host = file.HostName ?? file.Fqdn;
                return System.IO.Path.GetFileName(file.Path) + (string.IsNullOrEmpty(host) ? "" : "   |   " + host) +
                    (string.IsNullOrEmpty(file.IpAddress) ? "" : " (" + file.IpAddress + ")");
            }
        }

        public ChecklistStig SelectedStig
        {
            get { return stig; }
            set
            {
                if (!Set(ref stig, value)) return;
                Rows.Clear();
                SelectedRow = null;
                if (value != null) foreach (var r in value.Rules) Rows.Add(new RuleRow(r));
                Refilter();
            }
        }

        public RuleRow SelectedRow { get { return selectedRow; } set { Set(ref selectedRow, value); } }
        public bool IsLoading { get { return loading; } private set { Set(ref loading, value); } }
        public string Message { get { return message; } private set { Set(ref message, value); } }
        public string Counts { get { return counts; } private set { Set(ref counts, value); } }

        public string StatusFilter { get { return statusFilter; } set { if (Set(ref statusFilter, value ?? "All")) Refilter(); } }
        public string CatFilter { get { return catFilter; } set { if (Set(ref catFilter, value ?? "All")) Refilter(); } }
        public string SearchText { get { return search; } set { if (Set(ref search, value ?? "")) Refilter(); } }

        void Browse()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Open checklist",
                Filter = "STIG Viewer checklist (*.cklb)|*.cklb|All files (*.*)|*.*",
                InitialDirectory = main.Settings.EffectiveOutputPath
            };
            if (dlg.ShowDialog() == true) Load(dlg.FileName);
        }

        /// <summary>Reads the checklist off the UI thread and shows its first STIG.</summary>
        public void Load(string path)
        {
            requested = CklbReader.Canonical(path);
            int token = ++loadToken;
            IsLoading = true;
            Message = "Reading " + System.IO.Path.GetFileName(path) + "...";
            Background.Run(() => CklbReader.Read(path), f =>
            {
                if (token != loadToken) return;
                IsLoading = false;
                File = f;
                Stigs.Clear();
                foreach (var s in f.Stigs) Stigs.Add(s);
                Raise("HasManyStigs");
                SelectedStig = Stigs.FirstOrDefault();
                var known = Available.FirstOrDefault(x => string.Equals(x.Path, f.Path, StringComparison.OrdinalIgnoreCase));
                if (known == null)
                {
                    known = CklbReader.Describe(f.Path);
                    if (known != null) Available.Insert(0, known);
                }
                if (known != null) { listing = known; Raise("SelectedListing"); }
                Message = Stigs.Count == 0 ? "This checklist has no STIGs." : null;
            }, e =>
            {
                if (token != loadToken) return;
                IsLoading = false;
                Message = "Could not open " + System.IO.Path.GetFileName(path) + ": " + Background.Describe(e);
            });
        }

        bool Matches(RuleRow r)
        {
            if (statusFilter != "All" && r.Status != statusFilter) return false;
            if (catFilter != "All" && r.Cat != catFilter) return false;
            if (search.Length > 0)
            {
                string s = search.Trim();
                Func<string, bool> has = f => f != null && f.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0;
                if (!(has(r.Title) || has(r.GroupId) || has(r.StigId) || has(r.RuleId) || has(r.Ccis) || has(r.Comments))) return false;
            }
            return true;
        }

        void Refilter()
        {
            RowsView.Refresh();
            if (Rows.Count == 0) { Counts = null; return; }
            int shown = RowsView.Cast<object>().Count();
            Func<string, int> n = s => Rows.Count(x => x.Status == s);
            Counts = string.Format(CultureInfo.CurrentCulture, "{0} of {1} rules shown   |   Open {2}   Not a Finding {3}   Not Reviewed {4}   Not Applicable {5}",
                shown, Rows.Count, n("Open"), n("Not a Finding"), n("Not Reviewed"), n("Not Applicable"));
            if (selectedRow != null && !Matches(selectedRow)) SelectedRow = null;
        }
    }
}
