using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace CommandInjectionConfigFileTests
{
    // A persisted key=value configuration file. In the reported scenario the file is writable by an
    // unauthenticated settings page, so any value read back from it is attacker-controlled.
    public class ConfigFile
    {
        private readonly string _filePath;
        private readonly IDictionary<string, string> _settings = new Dictionary<string, string>();

        public ConfigFile(string filePath) { _filePath = filePath; }

        public void Load()
        {
            foreach (string line in File.ReadAllLines(_filePath)) // $ Source=config
            {
                string[] tokens = line.Split('=');
                if (tokens.Length >= 2)
                    _settings[tokens[0].ToLower()] = tokens[1];
            }
        }

        public string Get(string key)
        {
            key = key.ToLower();
            if (_settings.ContainsKey(key))
                return _settings[key];
            return string.Empty;
        }
    }

    public class DbProvider
    {
        private readonly string _clientExec;
        private readonly string _host;

        public DbProvider(ConfigFile configFile)
        {
            _clientExec = configFile.Get("client");
            _host = configFile.Get("host");
        }

        public bool Recreate()
        {
            string args = string.Format("--host={0} -f", _host);
            return ProcessRunner.RunWithInput(_clientExec, args, "create.sql") == 0;
        }
    }

    public static class ProcessRunner
    {
        public static int RunWithInput(string cmd, string args, string input)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = cmd, // $ Alert=config
                Arguments = args, // $ Alert=config
                UseShellExecute = false,
            };
            using (var process = new Process())
            {
                process.StartInfo = startInfo;
                process.Start();
                return 0;
            }
        }

        public static void RunDirect(ConfigFile configFile)
        {
            Process.Start(configFile.Get("client"), configFile.Get("host")); // $ Alert=config
        }
    }

    // Application startup: the configuration is loaded from disk, not from the current request.
    public static class Settings
    {
        public static void Init(string configPath)
        {
            var configFile = new ConfigFile(configPath);
            configFile.Load();
            new DbProvider(configFile).Recreate();
            ProcessRunner.RunDirect(configFile);
        }
    }
}
