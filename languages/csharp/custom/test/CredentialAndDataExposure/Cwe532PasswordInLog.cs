using Microsoft.Extensions.Logging;

namespace Cwe532
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        public override string ToString()
        {
            return $"Id: {Id} UserName: {Username} Password: {Password}";
        }

        public string SafeToString()
        {
            return $"Id: {Id} UserName: {Username} Password: ******";
        }
    }

    public class Article
    {
        public int Id { get; set; }
        public string Title { get; set; }

        public override string ToString()
        {
            return $"Id: {Id} Title: {Title}";
        }
    }

    public class UsersService
    {
        private readonly ILogger<UsersService> _logger;

        public UsersService(ILogger<UsersService> logger)
        {
            _logger = logger;
        }

        public void Create(User user, Article article)
        {
            // CWE-532: User.ToString() includes the password.
            _logger.LogInformation($"Creating the user {user.ToString()}"); // $ Alert
            // CWE-532: implicit ToString() through string interpolation.
            _logger.LogInformation($"Creating the user {user}"); // $ Alert
            // CWE-532: implicit ToString() through string concatenation.
            _logger.LogInformation("Creating the user " + user); // $ Alert
            // Safe: redacted representation.
            _logger.LogInformation($"Creating the user {user.SafeToString()}");
            // Safe: ToString() without credentials.
            _logger.LogInformation($"Creating the article {article}");
            // Safe: not a log sink.
            System.Console.Out.Flush();
            string s = user.ToString();
        }
    }
}
