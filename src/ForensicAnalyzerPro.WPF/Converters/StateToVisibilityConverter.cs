using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using ForensicAnalyzerPro.WPF.ViewModels;

namespace ForensicAnalyzerPro.WPF.Converters;

public class StateToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ScannerState state && parameter is string target)
        {
            return state.ToString() == target ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class ProgressToWidthConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int progress && parameter is string totalStr && int.TryParse(totalStr, out var total))
        {
            return (double)progress / 100 * total;
        }
        return 0.0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
