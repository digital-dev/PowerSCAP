using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;

namespace PowerScap.Gui
{
    public abstract class ObservableObject : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected bool Set<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            Raise(name);
            return true;
        }

        protected void Raise(string name)
        {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }
    }

    public class RelayCommand : ICommand
    {
        readonly Action<object> run;
        readonly Func<object, bool> can;

        public RelayCommand(Action<object> run, Func<object, bool> can = null)
        {
            this.run = run;
            this.can = can;
        }

        public RelayCommand(Action run, Func<bool> can = null)
            : this(_ => run(), can == null ? (Func<object, bool>)null : _ => can()) { }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public bool CanExecute(object parameter) { return can == null || can(parameter); }
        public void Execute(object parameter) { run(parameter); }
    }

    /// <summary>Runs work off the UI thread and continues on it. Errors go to the fail callback, never unhandled.</summary>
    public static class Background
    {
        /// <summary>The UI thread's context, also when called from script outside a dispatcher callback.</summary>
        public static SynchronizationContext UiContext()
        {
            return SynchronizationContext.Current ?? new System.Windows.Threading.DispatcherSynchronizationContext(System.Windows.Threading.Dispatcher.CurrentDispatcher);
        }

        public static void Run<T>(Func<T> work, Action<T> done, Action<Exception> fail)
        {
            var ui = UiContext();
            Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)
                .ContinueWith(t => ui.Post(_ =>
                {
                    if (t.IsFaulted)
                    {
                        var e = t.Exception.InnerExceptions.Count == 1 ? t.Exception.InnerException : t.Exception;
                        if (fail != null) fail(e);
                    }
                    else if (done != null) done(t.Result);
                }, null), TaskScheduler.Default);
        }

        public static void Run(Action work, Action done, Action<Exception> fail)
        {
            Run<object>(() => { work(); return null; }, _ => { if (done != null) done(); }, fail);
        }

        /// <summary>The message a person should see for an exception (inner causes of wrappers included).</summary>
        public static string Describe(Exception e)
        {
            while ((e is AggregateException || e is System.Reflection.TargetInvocationException) && e.InnerException != null) e = e.InnerException;
            return e.Message;
        }
    }

    /// <summary>false/null/empty to Visible, otherwise Collapsed (the inverse of BooleanToVisibilityConverter, also for objects).</summary>
    public class EmptyToVisibleConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool empty = value == null || (value is bool && !(bool)value) || (value is string && ((string)value).Length == 0) || (value is int && (int)value == 0);
            return empty ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) { throw new NotSupportedException(); }
    }

    /// <summary>true/non-null/non-empty to Visible, otherwise Collapsed.</summary>
    public class PresentToVisibleConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var v = (Visibility)new EmptyToVisibleConverter().Convert(value, targetType, parameter, culture);
            return v == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) { throw new NotSupportedException(); }
    }

    /// <summary>Binds a radio button to a string property: checked when the value equals the parameter.</summary>
    public class EqualsConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return string.Equals(System.Convert.ToString(value, culture), System.Convert.ToString(parameter, culture), StringComparison.OrdinalIgnoreCase);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool && (bool)value ? parameter : Binding.DoNothing;
        }
    }
}
