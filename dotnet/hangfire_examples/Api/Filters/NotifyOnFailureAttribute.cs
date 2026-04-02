namespace Api.Filters;

/// <summary>
/// Opt-in marker. Apply to a job class to receive a failure email
/// after all Hangfire retries are exhausted.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public class NotifyOnFailureAttribute : Attribute { }
