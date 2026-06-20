using System.Windows;
using WHCryptoManager.ViewModel;

namespace WHCryptoManager
{
    public partial class MainWindow : Window
    {
        public MainViewModel Vm { get; } = new MainViewModel();

        public MainWindow()
        {
            InitializeComponent();
            DataContext = Vm;
        }

        private void OnGenKey(object sender, RoutedEventArgs e) => Vm.GenerateMasterKey();

        private void OnGenLicense(object sender, RoutedEventArgs e) => Vm.GenerateLicense();

        private void OnAddIndicator(object sender, RoutedEventArgs e) => Vm.AddIndicators();

        private void OnRemoveIndicator(object sender, RoutedEventArgs e) => Vm.RemoveIndicator(Vm.SelectedIndicator);

        private void OnGenerate(object sender, RoutedEventArgs e)
        {
            genBtn.IsEnabled = false;
            try { Vm.GenerateClient(); }
            finally { genBtn.IsEnabled = true; }
        }
    }
}
