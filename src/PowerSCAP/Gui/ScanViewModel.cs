using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using PowerScap.Engine.Oval;
using PowerScap.Engine.Reports;
using PowerScap.Engine.Scan;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Gui
{
    /// <summary>One benchmark in a scan batch.</summary>
    public class ScanJob : ObservableObject
    {
        int done, total;
        string state = "Queued", message, currentRule;
        TimeSpan elapsed;

        public string Title { get; set; }
        public string ProfileTitle { get; set; }
        public ScanRequest Request { get; set; }
        public BenchmarkReport Report { get; set; }

        public int Done { get { return done; } set { if (Set(ref done, value)) { Raise("Percent"); Raise("ProgressText"); } } }
        public int Total { get { return total; } set { if (Set(ref total, value)) { Raise("Percent"); Raise("ProgressText"); } } }
        public double Percent { get { return total == 0 ? 0 : 100.0 * done / total; } }

        public string ProgressText
        {
            get
            {
                if (state == "Queued") return "Waiting";
                if (state == "Running") return total == 0 ? "Loading content..." : string.Format("Rule {0} of {1}", Math.Min(done + 1, total), total);
                return message ?? state;
            }
        }

        /// <summary>Queued, Running, Completed, Failed or Cancelled.</summary>
        public string State { get { return state; } set { if (Set(ref state, value)) { Raise("ProgressText"); Raise("IsRunning"); } } }
        public bool IsRunning { get { return state == "Running"; } }
        public string Message { get { return message; } set { if (Set(ref message, value)) Raise("ProgressText"); } }
        public string CurrentRule { get { return currentRule; } set { Set(ref currentRule, value); } }
        public TimeSpan Elapsed { get { return elapsed; } set { if (Set(ref elapsed, value)) Raise("ElapsedText"); } }
        public string ElapsedText
        {
            get
            {
                if (elapsed == TimeSpan.Zero) return "";
                return elapsed.TotalSeconds < 60 ? elapsed.TotalSeconds.ToString("0.0") + " s" : elapsed.ToString(@"m\:ss");
            }
        }
    }

    /// <summary>Step 3: runs the selected benchmarks on a worker thread, one after another, with cancel.</summary>
    public class ScanViewModel : ObservableObject
    {
        readonly MainViewModel main;
        CancellationTokenSource cts;
        bool running;
        string summaryPath, outputFolder, batchMessage;

        public ScanViewModel(MainViewModel main)
        {
            this.main = main;
            Jobs = new ObservableCollection<ScanJob>();
            CancelCommand = new RelayCommand(Cancel, () => IsRunning && cts != null && !cts.IsCancellationRequested);
            OpenFolderCommand = new RelayCommand(() => Shell.OpenFolder(outputFolder), () => outputFolder != null && Directory.Exists(outputFolder));
            OpenSummaryCommand = new RelayCommand(() => Shell.Open(summaryPath), () => summaryPath != null);
            ViewResultsCommand = new RelayCommand(() => main.Page = "Results", () => !IsRunning && Jobs.Any(j => j.Report != null));
        }

        public ObservableCollection<ScanJob> Jobs { get; private set; }
        public ICommand CancelCommand { get; private set; }
        public ICommand OpenFolderCommand { get; private set; }
        public ICommand OpenSummaryCommand { get; private set; }
        public ICommand ViewResultsCommand { get; private set; }

        public bool IsRunning
        {
            get { return running; }
            private set { if (Set(ref running, value)) Raise("HasNoJobs"); }
        }

        public bool HasNoJobs { get { return Jobs.Count == 0; } }

        public string BatchMessage
        {
            get { return batchMessage; }
            private set { Set(ref batchMessage, value); }
        }

        /// <summary>Starts a batch. Never shows a dialog: problems are reported on each job.</summary>
        public void Start(IList<BenchmarkItem> items)
        {
            if (IsRunning || items.Count == 0) return;
            main.Page = "Scan";
            if (!main.IsElevated && !main.Settings.AllowUnelevated)
            {
                BatchMessage = "Scans need administrator rights. Use \"Restart as administrator\", or allow unelevated scans in Settings (checks that need elevation will report errors).";
                return;
            }
            outputFolder = main.Settings.EffectiveOutputPath;
            summaryPath = null;
            Jobs.Clear();
            foreach (var i in items)
                Jobs.Add(new ScanJob
                {
                    Title = i.Title,
                    ProfileTitle = i.Profile == null ? "" : i.Profile.Title,
                    Request = new ScanRequest
                    {
                        ContentPath = i.Path,
                        ProfileId = i.Profile == null ? null : i.Profile.Id,
                        OutputPath = outputFolder,
                        Formats = main.Settings.Formats
                    }
                });
            Raise("HasNoJobs");
            BatchMessage = "Scanning " + Jobs.Count + (Jobs.Count == 1 ? " benchmark" : " benchmarks") + ". Results are written to " + outputFolder + ".";
            IsRunning = true;
            cts = new CancellationTokenSource();
            var token = cts.Token;
            var ui = Background.UiContext();
            var jobs = Jobs.ToList();
            Task.Factory.StartNew(() => RunBatch(jobs, ui, token), TaskCreationOptions.LongRunning)
                .ContinueWith(t => ui.Post(_ => Finish(jobs), null), TaskScheduler.Default);
        }

        void RunBatch(List<ScanJob> jobs, SynchronizationContext ui, CancellationToken token)
        {
            // One collector set for the batch: each folder and registry key is read once across benchmarks.
            var runner = new ScanRunner(CollectorRegistry.CreateDefault()) { HistoryRoot = ScanHistory.DefaultRoot() };
            foreach (var job in jobs)
            {
                var j = job;
                if (token.IsCancellationRequested) { ui.Post(_ => j.State = "Cancelled", null); continue; }
                ui.Post(_ => j.State = "Running", null);
                var sw = Stopwatch.StartNew();
                string warning = null;
                Action<string> onWarning = m => warning = m;
                runner.Warning += onWarning;
                // Progress is coalesced: the UI thread reads the latest value instead of queueing one post per rule.
                ScanProgress latest = null;
                int pending = 0;
                var progress = new SyncProgress<ScanProgress>(p =>
                {
                    latest = p;
                    if (Interlocked.Exchange(ref pending, 1) == 0)
                        ui.Post(_ =>
                        {
                            Interlocked.Exchange(ref pending, 0);
                            var l = latest;
                            j.Total = l.Total; j.Done = l.Done; j.CurrentRule = l.CurrentRuleId; j.Elapsed = sw.Elapsed;
                        }, null);
                });
                try
                {
                    var outcome = runner.Run(j.Request, progress, token);
                    var r = outcome.Report;
                    ui.Post(_ =>
                    {
                        j.Report = r;
                        j.Done = j.Total;
                        j.Elapsed = sw.Elapsed;
                        j.State = "Completed";
                        j.Message = string.Format("Score {0:0.##}%, {1} open ({2} CAT I)", r.DefaultScore, r.Count(XccdfResult.Fail), r.Open("CAT I")) +
                            (warning == null ? "" : ". " + warning);
                    }, null);
                }
                catch (OperationCanceledException)
                {
                    ui.Post(_ => { j.State = "Cancelled"; j.Message = "Cancelled; nothing was written."; }, null);
                }
                catch (Exception e)
                {
                    if (e is OutOfMemoryException) throw;
                    string m = Background.Describe(e);
                    ui.Post(_ => { j.State = "Failed"; j.Message = m; j.Elapsed = sw.Elapsed; }, null);
                }
                finally { runner.Warning -= onWarning; }
            }
        }

        void Finish(List<ScanJob> jobs)
        {
            IsRunning = false;
            var reports = jobs.Where(j => j.Report != null).Select(j => j.Report).ToList();
            try
            {
                summaryPath = ScanRunner.WriteSummary(reports, outputFolder);
            }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
                main.Status = "The summary page could not be written: " + e.Message;
            }
            int failed = jobs.Count(j => j.State == "Failed"), cancelled = jobs.Count(j => j.State == "Cancelled");
            BatchMessage = string.Format("Finished: {0} completed{1}{2}.", reports.Count,
                failed > 0 ? ", " + failed + " failed" : "", cancelled > 0 ? ", " + cancelled + " cancelled" : "");
            main.Status = BatchMessage;
            main.Results.AddReports(reports);
            CommandManager.InvalidateRequerySuggested();
        }

        void Cancel()
        {
            if (cts == null) return;
            cts.Cancel();
            BatchMessage = "Cancelling after the current rule...";
        }
    }

    static class Shell
    {
        public static void Open(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
            catch (Exception e)
            {
                // No program is associated with the file type (.cklb without STIG Viewer): show it in Explorer.
                if (e is System.ComponentModel.Win32Exception || e is InvalidOperationException) Select(path);
                else throw;
            }
        }

        public static void Select(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + path + "\"") { UseShellExecute = true });
        }

        public static void OpenFolder(string folder)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            Process.Start(new ProcessStartInfo("explorer.exe", "\"" + folder + "\"") { UseShellExecute = true });
        }
    }
}
