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
    }
}
