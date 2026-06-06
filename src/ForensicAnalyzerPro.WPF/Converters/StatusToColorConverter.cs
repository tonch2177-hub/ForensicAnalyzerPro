using System.Globalization;
using System.Windows.Data;

namespace ForensicAnalyzerPro.WPF.Converters;

public class StatusToColorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value?.ToString() switch
        {
            "Pending" => "#808080",
            "Running" => "#2196F3",
            "Completed" => "#4CAF50",
            "Failed" => "#F44336",
            "Cancelled" => "#FF9800",
            _ => "#808080"
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
