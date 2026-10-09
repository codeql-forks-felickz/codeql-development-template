using System;
using System.Collections.Generic;

namespace CommandInjectionTests
{
    // Web Forms page that persists a user-supplied client executable into a configuration object,
    // builds a database provider from it, and runs the executable via `Util.RunProcessWithInput`.
    // Shape taken from WebGoat.NET `RebuildDatabase` / `ConfigFile` / `MySqlDbProvider`.
    public static class DbConstants
    {
        public const string KEY_DB_TYPE = "dbtype";
        public const string KEY_CLIENT_EXEC = "client";
        public const string DB_TYPE_MYSQL = "MySql";
        public const string DB_TYPE_SQLITE = "Sqlite";
    }

    public class ConfigFile
    {
        private string _filePath;
        private IDictionary<string, string> _settings = new Dictionary<string, string>();

        public ConfigFile(string fileName) { _filePath = fileName; }

        public void Load()
        {
            foreach (string line in System.IO.File.ReadAllLines(_filePath))
            {
                string[] tokens = line.Split('=');
                if (tokens.Length >= 2)
                    _settings[tokens[0].ToLower()] = tokens[1];
            }
        }

        public void Save() { }

        public string Get(string key)
        {
            key = key.ToLower();
            if (_settings.ContainsKey(key))
                return _settings[key];
            return string.Empty;
        }

        public void Set(string key, string value) { _settings[key.ToLower()] = value; }

        public void Remove(string key) { _settings.Remove(key.ToLower()); }
    }

    public interface IDbProvider
    {
        bool RecreateGoatDb();
    }

    public class MySqlDbProvider : IDbProvider
    {
        private readonly string _clientExec;

        public MySqlDbProvider(ConfigFile configFile) { _clientExec = configFile.Get(DbConstants.KEY_CLIENT_EXEC); }

        public bool RecreateGoatDb() => Math.Abs(Util.RunProcessWithInput(_clientExec, "-f", "create.sql")) == 0;
    }

    public class SqliteDbProvider : IDbProvider
    {
        private readonly string _clientExec;

        public SqliteDbProvider(ConfigFile configFile) { _clientExec = configFile.Get(DbConstants.KEY_CLIENT_EXEC); }

        public bool RecreateGoatDb() => Math.Abs(Util.RunProcessWithInput(_clientExec, "", "create.sql")) == 0;
    }

    public class DbProviderFactory
    {
        public static IDbProvider Create(ConfigFile configFile)
        {
            configFile.Load();
            string dbType = configFile.Get(DbConstants.KEY_DB_TYPE);
            switch (dbType)
            {
                case DbConstants.DB_TYPE_MYSQL:
                    return new MySqlDbProvider(configFile);
                case DbConstants.DB_TYPE_SQLITE:
                    return new SqliteDbProvider(configFile);
                default:
                    throw new Exception(dbType);
            }
        }
    }

    public class Settings
    {
        public static IDbProvider CurrentDbProvider { get; set; }
        public static ConfigFile CurrentConfigFile { get; set; }
    }

    public partial class RebuildDatabase : System.Web.UI.Page
    {
        protected void btnRebuildDatabase_Click(object sender, EventArgs e)
        {
            ConfigFile configFile = Settings.CurrentConfigFile;
            UpdateConfigFile(configFile);
            Settings.CurrentDbProvider = DbProviderFactory.Create(configFile);
            Settings.CurrentDbProvider.RecreateGoatDb();
        }

        private void UpdateConfigFile(ConfigFile configFile)
        {
            if (string.IsNullOrEmpty(txtClientExecutable.Text))
                configFile.Remove(DbConstants.KEY_CLIENT_EXEC);
            else
                configFile.Set(DbConstants.KEY_CLIENT_EXEC, txtClientExecutable.Text); // $ Source=webforms
            configFile.Save();
        }
    }

    // Designer-generated part of the page.
    public partial class RebuildDatabase
    {
        protected global::System.Web.UI.WebControls.TextBox txtClientExecutable;
    }
}
