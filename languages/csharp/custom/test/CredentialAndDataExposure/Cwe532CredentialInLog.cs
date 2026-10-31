using System;
using System.Data.SqlClient;
using log4net;
using NLog;

namespace Cwe532Direct
{
    public class CustomerLogin
    {
        private ILog log = log4net.LogManager.GetLogger(typeof(CustomerLogin));

        // CWE-532: the plaintext password typed by the user is logged.
        public void LogOn(string email, string pwd)
        {
            log.Info("User " + email + " attempted to log in with password " + pwd); // $ Alert
        }

        // Safe: only the user name is logged.
        public void LogOnSafe(string email, string pwd)
        {
            log.Info("User " + email + " attempted to log in");
        }
    }

    public class DatabaseConnector
    {
        // CWE-532: the connection string, including its password, is logged.
        public void Bad()
        {
            Logger logger = NLog.LogManager.GetLogger("cwe_testcases_logger");
            string dbConnectionString = @"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=P@ssW0rd";
            try
            {
                using (SqlConnection dBConnection = new SqlConnection(dbConnectionString))
                {
                    dBConnection.Open();
                }
            }
            catch (SqlException exceptSql)
            {
                logger.Log(NLog.LogLevel.Warn, "Error getting database connection: " + dbConnectionString, exceptSql); // $ Alert
            }
        }

        // Safe: a non-sensitive message is logged.
        public void Good()
        {
            Logger logger = NLog.LogManager.GetLogger("cwe_testcases_logger");
            string dbConnectionString = @"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=P@ssW0rd";
            try
            {
                using (SqlConnection dBConnection = new SqlConnection(dbConnectionString))
                {
                    dBConnection.Open();
                }
            }
            catch (SqlException exceptSql)
            {
                logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }

        // Safe: a connection string without a password (integrated security) is logged.
        public void GoodIntegrated()
        {
            Logger logger = NLog.LogManager.GetLogger("cwe_testcases_logger");
            string dbConnectionString = "Data Source=(local);Integrated Security=true";
            logger.Log(NLog.LogLevel.Warn, "Connecting with " + dbConnectionString, null);
        }

        public void BadConsole()
        {
            string pwd = "example";
            Console.WriteLine("Database connection failed: " + pwd); // $ Alert
        }

        public void GoodConsole()
        {
            Console.WriteLine("Connection failed");
        }

        public void BadHtmlComment(System.Web.HttpResponse response)
        {
            string pwd = "example";
            response.Write($"<!-- Database connection: {pwd} -->"); // $ Alert
        }

        public void GoodHtmlComment(System.Web.HttpResponse response)
        {
            response.Write("<!-- Database connection failed -->");
        }

        public void BadSensitiveDataLogging()
        {
            new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder().EnableSensitiveDataLogging(); // $ Alert
        }

        public void GoodDetailedErrorsOnly()
        {
            new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder().EnableDetailedErrors();
        }

        public void GoodSensitiveDataLoggingDisabled()
        {
            new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder().EnableSensitiveDataLogging(false);
        }
    }
}
