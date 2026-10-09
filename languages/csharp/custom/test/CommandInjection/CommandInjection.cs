using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace CommandInjectionTests
{
    public class CommandRequest
    {
        public string Command { get; set; }
    }

    // ASP.NET Core controller action with a `[FromBody]` request model.
    [ApiController]
    public class CommandController : ControllerBase
    {
        [HttpPost("run")]
        public IActionResult Run([FromBody] CommandRequest req) // $ Source=run
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + req.Command); // $ Alert=run
            Process.Start(psi);
            return Ok();
        }

        [HttpPost("run-helper")]
        public IActionResult RunHelper([FromBody] CommandRequest req) // $ Source=helper
        {
            Util.RunProcessWithInput(req.Command, "", "input.sql");
            return Ok();
        }

        [HttpPost("run-enumerable")]
        public IActionResult RunEnumerable([FromBody] CommandRequest req) // $ Source=enumerable
        {
            Process.Start("/bin/sh", new List<string> { "-c", req.Command }); // $ Alert=enumerable
            return Ok();
        }

        [HttpPost("run-argument-list")]
        public IActionResult RunArgumentList([FromBody] CommandRequest req)
        {
            var psi = new ProcessStartInfo("/bin/sh");
            psi.ArgumentList.Add("-c");
            // Not detected: taint stored in `ProcessStartInfo.ArgumentList` elements does not reach the
            // `Process.Start(psi)` sink, and C# MaD sink inputs cannot express `Property[..].Element` paths.
            psi.ArgumentList.Add(req.Command); // $ MISSING: Alert
            Process.Start(psi);
            return Ok();
        }

        [HttpPost("run-constant")]
        public IActionResult RunConstant([FromBody] CommandRequest req)
        {
            // GOOD: the command line does not depend on user input.
            Process.Start("cmd.exe", "/c dir");
            return Ok();
        }

        [HttpPost("run-int")]
        public IActionResult RunInt(int count)
        {
            // GOOD: simple types are sanitized.
            Process.Start("ping", "-n " + count + " localhost");
            return Ok();
        }
    }

    // ASP.NET Core minimal API handler.
    public static class MinimalApi
    {
        public static void MapRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/run", (CommandRequest req) => // $ Source=minimal
            {
                var psi = new ProcessStartInfo("cmd.exe", "/c " + req.Command); // $ Alert=minimal
                Process.Start(psi);
            });
        }
    }

    // Helper that wraps `Process.Start` (shape taken from WebGoat.NET `Util.RunProcessWithInput`).
    public class Util
    {
        public static int RunProcessWithInput(string cmd, string args, string input)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = cmd, // $ Alert=helper Alert=webforms
                Arguments = args,
                UseShellExecute = false,
            };
            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                process.Start();
                return 0;
            }
        }
    }
}
