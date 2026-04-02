namespace Api.Settings;

public class EmailSettings
{
    public string FromAddress { get; set; } = string.Empty;
    public string ToAddress { get; set; } = string.Empty;
    public string SmtpHost { get; set; } = string.Empty;
}
