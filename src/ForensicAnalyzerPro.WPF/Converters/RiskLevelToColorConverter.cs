using System.Globalization;
using System.Windows.Data;

namespace ForensicAnalyzerPro.WPF.Converters;

public class RiskLevelToColorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value?.ToString() switch
        {
            "None" => "#808080",
            "Low" => "#4CAF50",
            "Medium" => "#FF9800",
            "High" => "#F44336",
            "Critical" => "#8B0000",
            _ => "#808080"
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
