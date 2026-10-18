using System.Collections.ObjectModel;
using System.Windows.Input;
using PowerScap.Engine.Profile;

namespace PowerScap.Gui
{
    /// <summary>Step 1: the detected machine profile.</summary>
    public class SystemViewModel : ObservableObject
    {
        readonly MainViewModel main;
        SystemProfile profile;
        bool loading;

        public SystemViewModel(MainViewModel main)
        {
            this.main = main;
            Products = new ObservableCollection<DetectedProduct>();
            RefreshCommand = new RelayCommand(Refresh, () => !IsLoading);
        }

        public ObservableCollection<DetectedProduct> Products { get; private set; }
        public ICommand RefreshCommand { get; private set; }

        public SystemProfile Profile
        {
            get { return profile; }
            private set { Set(ref profile, value); }
        }

        public bool IsLoading
        {
            get { return loading; }
            private set { Set(ref loading, value); }
        }

        public void Refresh()
        {
            if (IsLoading) return;
            IsLoading = true;
            Background.Run(() => SystemProfile.Collect(), p =>
            {
                IsLoading = false;
                Profile = p;
                Products.Clear();
                foreach (var x in p.Products) Products.Add(x);
                main.OnProfileLoaded(p);
            }, e =>
            {
                IsLoading = false;
                main.Status = "Could not profile this machine: " + Background.Describe(e);
            });
        }
    }
}
