using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Data;
using System.Windows.Input;
using PowerScap.Engine.Reports;
using PowerScap.Engine.Scan;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Gui
{
    /// <summary>A rule in the findings list, with STIG Viewer status names.</summary>
    public class RuleRow
    {
        public RuleRow(RuleReport rule)
        {
            Rule = rule;
            Status = StatusOf(rule.Result);
        }

        public RuleReport Rule { get; private set; }
        public string Status { get; private set; }
        public string Cat { get { return Rule.Cat; } }
        public string GroupId { get { return Rule.GroupId; } }
        public string StigId { get { return Rule.StigId; } }
        public string RuleId { get { return Rule.RuleId; } }
        public string Title { get { return Rule.Title; } }
        public string Source { get { return Rule.Source ?? "SCAP"; } }
        public string Ccis { get { return string.Join(", ", Rule.Ccis); } }
        public string Discussion { get { return Rule.Discussion; } }
        public string CheckText { get { return Rule.CheckText; } }
        public string FixText { get { return Rule.FixText; } }
        public string Details { get { return Rule.Details; } }
        public string XccdfResult { get { return Rule.ResultText; } }

        /// <summary>Set when a previous scan of the benchmark had a different status for this rule.</summary>
        public bool Changed { get; set; }
        public string PreviousStatus { get; set; }
        public string ChangeText { get { return Changed ? (PreviousStatus == null ? "New rule" : "Was " + PreviousStatus) : null; } }

        public static string StatusOf(XccdfResult r)
        {
            switch (r)
            {
                case Engine.Xccdf.XccdfResult.Pass: return "Not a Finding";
                case Engine.Xccdf.XccdfResult.Fail: return "Open";
                case Engine.Xccdf.XccdfResult.NotApplicable: return "Not Applicable";
                case Engine.Xccdf.XccdfResult.Error:
                case Engine.Xccdf.XccdfResult.Unknown: return "Error";
                default: return "Not Reviewed";
            }
        }
    }

    /// <summary>One scan of a benchmark (from this session or the history).</summary>
    public class RunOption
    {
        public HistoryEntry Entry { get; set; }
        public BenchmarkReport Report { get; set; }
        public DateTime Start { get; set; }
        public double Score { get; set; }
        public string Label { get { return string.Format(CultureInfo.CurrentCulture, "{0:yyyy-MM-dd HH:mm}   {1:0.##}%", Start, Score); } }
        public override string ToString() { return Label; }
    }

    /// <summary>A score tile: the newest scan of one benchmark, with its earlier scans.</summary>
    public class ResultTile : ObservableObject
    {
        public ResultTile() { Runs = new ObservableCollection<RunOption>(); }

        public string BenchmarkId { get; set; }
        public string Title { get; set; }
        public string Version { get; set; }
        public double Score { get; set; }
        public int Open { get; set; }
        public int Cat1 { get; set; }
        public int Cat2 { get; set; }
        public int Cat3 { get; set; }
        public DateTime Start { get; set; }
        public ObservableCollection<RunOption> Runs { get; private set; }
        public string ScoreText { get { return Score.ToString("0.#", CultureInfo.CurrentCulture) + "%"; } }
        public string When { get { return Start.ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture); } }
        /// <summary>fail when CAT I findings are open, warn for other open findings, else pass.</summary>
        public string Kind { get { return Cat1 > 0 ? "fail" : Open > 0 ? "warn" : "pass"; } }
    }

    /// <summary>Step 4: score tiles, the filterable findings list and the rule detail panel.</summary>
    public class ResultsViewModel : ObservableObject
    {
        public static readonly string[] StatusChoices = { "All", "Open", "Not a Finding", "Not Reviewed", "Not Applicable", "Error" };
        public static readonly string[] CatChoices = { "All", "CAT I", "CAT II", "CAT III" };
        public static readonly string[] SourceChoices = { "All", "SCAP" };

        readonly MainViewModel main;
        readonly Dictionary<string, BenchmarkReport> loaded = new Dictionary<string, BenchmarkReport>(StringComparer.OrdinalIgnoreCase);
        readonly List<BenchmarkReport> session = new List<BenchmarkReport>();
        bool loadedOnce, loading;
        ResultTile tile;
        RunOption run;
        BenchmarkReport report;
        RuleRow selectedRow;
        string statusFilter = "All", catFilter = "All", sourceFilter = "All", search = "", message, counts;
        bool changedOnly, hasPrevious;
        int loadToken;

        public ResultsViewModel(MainViewModel main)
        {
            this.main = main;
            Tiles = new ObservableCollection<ResultTile>();
            Rows = new ObservableCollection<RuleRow>();
            RowsView = CollectionViewSource.GetDefaultView(Rows);
            RowsView.Filter = o => Matches((RuleRow)o);
            OpenFileCommand = new RelayCommand(p => OpenFile(Convert.ToString(p)), p => FileFor(Convert.ToString(p)) != null);
            OpenFolderCommand = new RelayCommand(() => Shell.Select(FileFor("XCCDF")), () => FileFor("XCCDF") != null);
            RefreshCommand = new RelayCommand(Refresh, () => !IsLoading);
            ClearFiltersCommand = new RelayCommand(() => { StatusFilter = "All"; CatFilter = "All"; SourceFilter = "All"; SearchText = ""; ChangedOnly = false; });
            ShowStatusCommand = new RelayCommand(p => StatusFilter = Convert.ToString(p));
        }

        public ObservableCollection<ResultTile> Tiles { get; private set; }
        public ObservableCollection<RuleRow> Rows { get; private set; }
        public ICollectionView RowsView { get; private set; }
        public ICommand OpenFileCommand { get; private set; }
        public ICommand OpenFolderCommand { get; private set; }
        public ICommand RefreshCommand { get; private set; }
        public ICommand ClearFiltersCommand { get; private set; }
        public ICommand ShowStatusCommand { get; private set; }

        public string[] Statuses { get { return StatusChoices; } }
        public string[] Cats { get { return CatChoices; } }
        public string[] Sources { get { return SourceChoices; } }

        public bool IsLoading { get { return loading; } private set { Set(ref loading, value); } }
        public string Message { get { return message; } private set { Set(ref message, value); } }
        public string Counts { get { return counts; } private set { Set(ref counts, value); } }
        public bool HasPrevious { get { return hasPrevious; } private set { Set(ref hasPrevious, value); } }
        public BenchmarkReport Report { get { return report; } private set { if (Set(ref report, value)) Raise("ReportHeader"); } }

        public string ReportHeader
        {
            get
            {
                if (report == null) return null;
                return string.Format(CultureInfo.CurrentCulture, "{0}  |  {1}  |  {2}  |  scanned {3:yyyy-MM-dd HH:mm}", report.StigName ?? report.Title,
                    VersionText(report), report.ProfileTitle ?? report.ProfileId, report.Start);
            }
        }

        /// <summary>STIG version and release as STIG Viewer shows them ("V2R6"), else the benchmark version.</summary>
        public static string VersionText(BenchmarkReport r)
        {
            var m = System.Text.RegularExpressions.Regex.Match(r.StigReleaseInfo ?? r.ReleaseInfo ?? "", @"Release:\s*(\d+)");
            if (!string.IsNullOrEmpty(r.StigVersion) && m.Success) return "V" + r.StigVersion + "R" + m.Groups[1].Value;
            return "Version " + (r.StigVersion ?? r.Version);
        }

        public ResultTile SelectedTile
        {
            get { return tile; }
            set
            {
                if (!Set(ref tile, value)) return;
                SelectedRun = value == null ? null : value.Runs.FirstOrDefault();
            }
        }

        public RunOption SelectedRun
        {
            get { return run; }
            set
            {
                if (!Set(ref run, value)) return;
                LoadRun(value);
            }
        }

        public RuleRow SelectedRow { get { return selectedRow; } set { Set(ref selectedRow, value); } }

        public string StatusFilter { get { return statusFilter; } set { if (Set(ref statusFilter, value ?? "All")) Refilter(); } }
        public string CatFilter { get { return catFilter; } set { if (Set(ref catFilter, value ?? "All")) Refilter(); } }
        public string SourceFilter { get { return sourceFilter; } set { if (Set(ref sourceFilter, value ?? "All")) Refilter(); } }
        public string SearchText { get { return search; } set { if (Set(ref search, value ?? "")) Refilter(); } }
        public bool ChangedOnly { get { return changedOnly; } set { if (Set(ref changedOnly, value)) Refilter(); } }

        public void EnsureLoaded()
        {
            if (!loadedOnce) Refresh();
        }

        /// <summary>Reports from a scan that just finished; they are shown without reading them back from the history.</summary>
        public void AddReports(IList<BenchmarkReport> reports)
        {
            session.AddRange(reports);
            if (reports.Count > 0) Refresh(reports[0].BenchmarkId);
        }

        public void Refresh() { Refresh(null); }

        void Refresh(string select)
        {
            loadedOnce = true;
            IsLoading = true;
            string keep = select ?? (tile == null ? null : tile.BenchmarkId);
            var root = ScanHistory.DefaultRoot();
            Background.Run(() => new ScanHistory(root).List(), entries =>
            {
                IsLoading = false;
                BuildTiles(entries);
                SelectedTile = Tiles.FirstOrDefault(t => t.BenchmarkId == keep) ?? Tiles.FirstOrDefault();
                Message = Tiles.Count == 0 ? "No scans yet. Pick benchmarks on the Content page and scan." : null;
            }, e =>
            {
                IsLoading = false;
                BuildTiles(new List<HistoryEntry>());
                SelectedTile = Tiles.FirstOrDefault();
                Message = "The scan history could not be read: " + Background.Describe(e);
            });
        }

        void BuildTiles(IList<HistoryEntry> entries)
        {
            var runs = entries.Select(e => new RunOption { Entry = e, Start = e.Start, Score = e.Score }).ToList();
            foreach (var r in session)
            {
                // A session report whose history save failed still shows; one that was saved matches its entry.
                var match = runs.FirstOrDefault(x => x.Entry != null && x.Entry.BenchmarkId == r.BenchmarkId && Math.Abs((x.Start - r.Start).TotalSeconds) < 1);
                if (match != null) match.Report = r;
                else runs.Add(new RunOption { Report = r, Start = r.Start, Score = r.DefaultScore });
            }
            Tiles.Clear();
            foreach (var g in runs.GroupBy(BenchmarkOf).OrderBy(g => TitleOf(g.OrderByDescending(x => x.Start).First()), StringComparer.OrdinalIgnoreCase))
            {
                var ordered = g.OrderByDescending(x => x.Start).ToList();
                var newest = ordered[0];
                var t = new ResultTile { BenchmarkId = g.Key, Title = TitleOf(newest), Start = newest.Start, Score = newest.Score };
                if (newest.Entry != null)
                {
                    t.Version = newest.Entry.Version; t.Open = newest.Entry.Open; t.Cat1 = newest.Entry.Cat1; t.Cat2 = newest.Entry.Cat2; t.Cat3 = newest.Entry.Cat3;
                }
                else
                {
                    var r = newest.Report;
                    t.Version = r.StigVersion ?? r.Version; t.Open = r.Count(Engine.Xccdf.XccdfResult.Fail);
                    t.Cat1 = r.Open("CAT I"); t.Cat2 = r.Open("CAT II"); t.Cat3 = r.Open("CAT III");
                }
                foreach (var o in ordered) t.Runs.Add(o);
                Tiles.Add(t);
            }
        }

        static string BenchmarkOf(RunOption r) { return r.Entry != null ? r.Entry.BenchmarkId : r.Report.BenchmarkId; }
        static string TitleOf(RunOption r) { return r.Entry != null ? r.Entry.Title : (r.Report.StigName ?? r.Report.Title); }

        void LoadRun(RunOption r)
        {
            int token = ++loadToken;
            Rows.Clear();
            SelectedRow = null;
            Report = null;
            HasPrevious = false;
            Counts = null;
            if (r == null) return;
            RunOption previous = null;
            if (tile != null)
            {
                int i = tile.Runs.IndexOf(r);
                if (i >= 0 && i + 1 < tile.Runs.Count) previous = tile.Runs[i + 1];
            }
            IsLoading = true;
            Background.Run(() => new { Current = Load(r), Previous = previous == null ? null : Load(previous) }, x =>
            {
                if (token != loadToken) return;
                IsLoading = false;
                Report = x.Current;
                Dictionary<string, string> before = null;
                if (x.Previous != null)
                {
                    before = new Dictionary<string, string>(StringComparer.Ordinal);
                    foreach (var rule in x.Previous.Rules) before[rule.RuleId] = RuleRow.StatusOf(rule.Result);
                }
                HasPrevious = before != null;
                if (!HasPrevious) ChangedOnly = false;
                foreach (var rule in x.Current.Rules)
                {
                    var row = new RuleRow(rule);
                    string was;
                    if (before != null)
                    {
                        bool known = before.TryGetValue(rule.RuleId, out was);
                        row.Changed = !known || was != row.Status;
                        row.PreviousStatus = known ? was : null;
                    }
                    Rows.Add(row);
                }
                Refilter();
            }, e =>
            {
                if (token != loadToken) return;
                IsLoading = false;
                Message = "This scan could not be loaded: " + Background.Describe(e);
            });
        }

        BenchmarkReport Load(RunOption r)
        {
            if (r.Report != null) return r.Report;
            BenchmarkReport cached;
            lock (loaded)
                if (loaded.TryGetValue(r.Entry.ReportPath, out cached)) return cached;
            var rep = new ScanHistory(Path.GetDirectoryName(r.Entry.ReportPath)).Load(r.Entry.ReportPath);
            lock (loaded) loaded[r.Entry.ReportPath] = rep;
            return rep;
        }

        bool Matches(RuleRow r)
        {
            if (statusFilter != "All" && r.Status != statusFilter) return false;
            if (catFilter != "All" && r.Cat != catFilter) return false;
            if (sourceFilter != "All" && r.Source != sourceFilter) return false;
            if (changedOnly && !r.Changed) return false;
            if (search.Length > 0)
            {
                string s = search.Trim();
                Func<string, bool> has = f => f != null && f.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0;
                if (!(has(r.Title) || has(r.GroupId) || has(r.StigId) || has(r.RuleId) || has(r.Ccis))) return false;
            }
            return true;
        }

        void Refilter()
        {
            RowsView.Refresh();
            int shown = RowsView.Cast<object>().Count();
            if (Rows.Count == 0) { Counts = null; return; }
            Func<string, int> n = s => Rows.Count(x => x.Status == s);
            Counts = string.Format(CultureInfo.CurrentCulture, "{0} of {1} rules shown   |   Open {2}   Not a Finding {3}   Not Reviewed {4}   Not Applicable {5}   Error {6}",
                shown, Rows.Count, n("Open"), n("Not a Finding"), n("Not Reviewed"), n("Not Applicable"), n("Error"));
            if (selectedRow != null && !Matches(selectedRow)) SelectedRow = null;
        }

        string FileFor(string kind)
        {
            if (report == null || string.IsNullOrEmpty(kind)) return null;
            string f;
            return report.Files != null && report.Files.TryGetValue(kind, out f) && File.Exists(f) ? f : null;
        }

        void OpenFile(string kind)
        {
            try { Shell.Open(FileFor(kind)); }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
                main.Status = "Could not open the file: " + e.Message;
            }
        }
    }
}
