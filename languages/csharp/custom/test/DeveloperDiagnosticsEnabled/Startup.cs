using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace Blog
{
    public class Startup
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // BAD: the developer exception page is enabled in every environment.
            app.UseDeveloperExceptionPage(); // $ Alert
            app.UseDatabaseErrorPage(); // $ Alert
        }
    }

    public class GoodStartup
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: restricted to the development environment.
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/error");
            }
        }
    }

    public class GoodStartupNegated
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: restricted to the development environment.
            if (!env.IsDevelopment())
                app.UseExceptionHandler("/error");
            else
                app.UseDeveloperExceptionPage();
        }
    }

    public class GoodStartupEarlyReturn
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: only reached in the development environment.
            if (!env.IsEnvironment("Development"))
            {
                app.UseExceptionHandler("/error");
                return;
            }
            app.UseDeveloperExceptionPage();
        }
    }

    public class GoodStartupEnvironmentName
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: restricted to the development environment.
            if (env.EnvironmentName == "Development")
                app.UseDeveloperExceptionPage();
        }
    }

    public class BadStartupUnrelatedCondition
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, bool verbose)
        {
            // BAD: the condition is not an environment check.
            if (verbose)
                app.UseDeveloperExceptionPage(); // $ Alert
        }
    }

    public class BadStartupElseBranch
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // BAD: enabled outside the development environment.
            if (env.IsDevelopment())
                app.UseExceptionHandler("/error");
            else
                app.UseDeveloperExceptionPage(); // $ Alert
        }
    }

    public class BadStartupUnrelatedThrow
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, string connStr)
        {
            // BAD: the earlier environment check does not restrict the call below.
            if (env.IsProduction() && connStr == null)
                throw new InvalidOperationException("missing config");
            app.UseDeveloperExceptionPage(); // $ Alert
        }
    }

    public class BadStartupReturnInDevelopment
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseExceptionHandler("/error");
                return;
            }
            // BAD: only reached outside the development environment.
            app.UseDeveloperExceptionPage(); // $ Alert
        }
    }

    public class GoodStartupNotProduction
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: not enabled in production.
            if (!env.IsProduction())
                app.UseDeveloperExceptionPage();
        }
    }

    public class GoodStartupConjunction
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, bool verbose)
        {
            // GOOD: restricted to the development environment.
            if (verbose && env.IsDevelopment())
                app.UseDeveloperExceptionPage();
        }
    }

    public class GoodStartupConvention
    {
        // GOOD: ASP.NET Core only calls `ConfigureDevelopment` in the development environment.
        public void ConfigureDevelopment(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
        }
    }

    public class GoodStartupLocalVariable
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // GOOD: restricted to the development environment.
            var isDevelopment = env.IsDevelopment();
            if (isDevelopment)
                app.UseDeveloperExceptionPage();
        }
    }
}
