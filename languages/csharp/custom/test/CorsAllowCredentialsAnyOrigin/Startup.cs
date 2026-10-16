using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace CorsApp
{
    public class Startup
    {
        // Wildcard origin combined with credentials in a fluent chain.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials() // $ Alert
                        .Build());
            });
        }

        // Every origin is reflected back, together with credentials.
        public void ReflectAnyOrigin(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                    builder.SetIsOriginAllowed(origin => true)
                        .AllowCredentials()); // $ Alert
            });
        }

        // Same misconfiguration with separate statements on one builder.
        public CorsPolicy SeparateStatements()
        {
            var builder = new CorsPolicyBuilder();
            builder.AllowAnyOrigin();
            builder.AllowAnyHeader();
            builder.AllowCredentials(); // $ Alert
            return builder.Build();
        }

        // Safe: credentials are only allowed for an explicit list of trusted origins.
        public void TrustedOrigins(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("Trusted",
                    builder => builder.WithOrigins("https://app.example.com")
                        .AllowAnyHeader()
                        .AllowCredentials());
            });
        }

        // Safe: any origin, but no credentials.
        public void PublicApi(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("Public",
                    builder => builder.AllowAnyOrigin().AllowAnyMethod());
            });
        }

        // Safe: the origin predicate actually validates the origin.
        public void ValidatedOrigin(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                    builder.SetIsOriginAllowed(origin => origin == "https://app.example.com")
                        .AllowCredentials());
            });
        }

        // Safe: two different builders.
        public void DifferentBuilders()
        {
            var anyOrigin = new CorsPolicyBuilder().AllowAnyOrigin();
            var trusted = new CorsPolicyBuilder("https://app.example.com").AllowCredentials();
        }
    }
}
