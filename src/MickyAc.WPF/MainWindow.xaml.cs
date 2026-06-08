using System.Windows;
using System.Windows.Input;
using MickyAc.WPF.ViewModels;

namespace MickyAc.WPF;

public partial class MainWindow : Window
{
    private readonly ScannerViewModel _vm;

    public MainWindow(ScannerViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = vm;

        Loaded += (_, _) =>
        {
            PinInput.Focus();
        };

        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape && _vm.CurrentState == ScannerState.Scanning)
            {
                _vm.Cancel();
                Close();
            }
        };
    }

    private void PinInput_PreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        e.Handled = !char.IsDigit(e.Text, 0);
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _vm.Cancel();
        Close();
    }
}
