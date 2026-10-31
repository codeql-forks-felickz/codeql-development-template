// Minimal stubs modelled on Microsoft.Extensions.Logging public API signatures.
// As in the real library, the `LoggerExtensions` helpers forward the message to
// `ILogger.Log`. Because these stubs are extracted from source, `cs/log-forging`
// analyzes the extension methods interprocedurally and reports the forwarded
// message here instead of at the `LogError` call site.
namespace Microsoft.Extensions.Logging
{
    public enum LogLevel { Information, Error }

    public interface ILogger
    {
        void Log(LogLevel logLevel, string message, object[] args);
    }

    public interface ILogger<out TCategoryName> : ILogger { }

    public static class LoggerExtensions
    {
        public static void LogError(this ILogger logger, string message, params object[] args) =>
            logger.Log(LogLevel.Error, message, args); // $ Alert

        public static void LogInformation(this ILogger logger, string message, params object[] args) =>
            logger.Log(LogLevel.Information, message, args);
    }
}
