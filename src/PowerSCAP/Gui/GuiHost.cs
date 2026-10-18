using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Threading;
using PowerScap.Engine.Ncp;

namespace PowerScap.Gui
{
    /// <summary>Creates the WPF application and main window from the loose XAML files and shows it.</summary>
    public static class GuiHost
    {
        /// <summary>Application-wide resources the XAML refers to by key (converters live in this assembly).</summary>
        public static Application EnsureApplication(string guiDir, string theme)
        {
            ThemeManager.ThemeDirectory = Path.Combine(guiDir, "Themes");
            var app = Application.Current;
            if (app == null)
            {
                app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                app.DispatcherUnhandledException += OnUnhandled;
            }
            app.Resources["EmptyToVisible"] = new EmptyToVisibleConverter();
            app.Resources["PresentToVisible"] = new PresentToVisibleConverter();
            app.Resources["EqualsTo"] = new EqualsConverter();
            app.Resources["BoolToVisible"] = new System.Windows.Controls.BooleanToVisibilityConverter();
            ThemeManager.Apply(app, theme);
            return app;
        }

        public static Window LoadWindow(string guiDir)
        {
            using (var s = File.OpenRead(Path.Combine(guiDir, @"Views\MainWindow.xaml")))
                return (Window)XamlReader.Load(s);
        }

        /// <summary>The main window bound to a new view-model (not shown yet).</summary>
        public static Window CreateWindow(string guiDir, GuiSettings settings, string settingsPath, IHttpTransport http, string launcherScript)
        {
            EnsureApplication(guiDir, settings.Theme);
            var window = LoadWindow(guiDir);
            // Wide enough for the findings list beside the rule detail, within the screen.
            var area = SystemParameters.WorkArea;
            window.Width = Math.Max(window.MinWidth, Math.Min(1500, area.Width - 40));
            window.Height = Math.Max(window.MinHeight, Math.Min(940, area.Height - 40));
            var vm = new MainViewModel(settings, settingsPath, http, launcherScript);
            window.DataContext = vm;
            vm.CloseRequested += (s, e) => window.Close();
            window.SourceInitialized += (s, e) => ThemeManager.ApplyTitleBar(window, ThemeManager.Resolve(settings.Theme) == "Dark");
            window.ContentRendered += (s, e) => vm.Start();
            window.Closing += (s, e) =>
            {
                if (!vm.Scan.IsRunning) return;
                // A scan is a single long operation; closing mid-scan would abandon it without results.
                var answer = MessageBox.Show(window, "A scan is running. Close PowerSCAP and cancel it?", "PowerSCAP", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) e.Cancel = true;
                else vm.Scan.CancelCommand.Execute(null);
            };
            return window;
        }

        /// <summary>Shows the app and returns when the window closes.</summary>
        public static void Run(string guiDir, string launcherScript)
        {
            string settingsPath = GuiSettings.DefaultPath();
            CreateWindow(guiDir, GuiSettings.Load(settingsPath), settingsPath, new HttpTransport(), launcherScript).ShowDialog();
        }

        /// <summary>Saves what the window shows now as a PNG (tests and documentation; the window may be off screen).</summary>
        public static void Snapshot(Window window, string path)
        {
            var root = (FrameworkElement)window.Content;
            int w = (int)Math.Ceiling(root.ActualWidth), h = (int)Math.Ceiling(root.ActualHeight);
            var bmp = new System.Windows.Media.Imaging.RenderTargetBitmap(w, h, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            var visual = new System.Windows.Media.DrawingVisual();
            using (var dc = visual.RenderOpen())
            {
                dc.DrawRectangle(window.Background, null, new Rect(0, 0, w, h));
                dc.DrawRectangle(new System.Windows.Media.VisualBrush(root), null, new Rect(0, 0, w, h));
            }
            bmp.Render(visual);
            var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
            enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bmp));
            using (var f = File.Create(path)) enc.Save(f);
        }

        /// <summary>Processes UI work (bindings, background completions) for a while without a modal loop.</summary>
        public static void Pump(TimeSpan duration)
        {
            var frame = new DispatcherFrame();
            var timer = new DispatcherTimer { Interval = duration };
            timer.Tick += (s, e) => { timer.Stop(); frame.Continue = false; };
            timer.Start();
            Dispatcher.PushFrame(frame);
        }

        static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            // Keep the window (and the PowerShell host) alive: log, show the message, carry on.
            try
            {
                string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"PowerSCAP\gui.log");
                Directory.CreateDirectory(Path.GetDirectoryName(log));
                File.AppendAllText(log, DateTime.Now.ToString("s") + " " + e.Exception + Environment.NewLine, Encoding.UTF8);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            var w = Application.Current == null ? null : Application.Current.MainWindow ?? (Application.Current.Windows.Count > 0 ? Application.Current.Windows[0] : null);
            var vm = w == null ? null : w.DataContext as MainViewModel;
            if (vm != null) vm.Status = "Unexpected error: " + Background.Describe(e.Exception) + " (details in %LOCALAPPDATA%\\PowerSCAP\\gui.log)";
            e.Handled = true;
        }
    }
}
