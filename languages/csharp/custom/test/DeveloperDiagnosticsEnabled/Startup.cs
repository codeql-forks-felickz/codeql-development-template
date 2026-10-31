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
}
