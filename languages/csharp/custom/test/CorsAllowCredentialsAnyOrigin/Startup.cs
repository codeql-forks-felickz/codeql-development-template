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

        // The calls after the reassignment share the new builder definition.
        public CorsPolicy ReassignedBuilder()
        {
            CorsPolicyBuilder builder = new CorsPolicyBuilder("https://old.example.com");
            builder = new CorsPolicyBuilder();
            builder.AllowAnyOrigin();
            builder.AllowCredentials(); // $ Alert
            return builder.Build();
        }

        // The builder is reassigned between configuration calls.
        public CorsPolicy DifferentBuilderAfterReassignment()
        {
            var builder = new CorsPolicyBuilder().AllowAnyOrigin();
            builder = new CorsPolicyBuilder("https://app.example.com");
            builder.AllowCredentials();
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

        // Safe: a later credential setting disables credentials before the policy is built.
        public CorsPolicy CredentialsDisabled()
        {
            var builder = new CorsPolicyBuilder();
            builder.AllowAnyOrigin().AllowCredentials();
            builder.DisallowCredentials();
            return builder.Build();
        }

        // Safe: the final origin predicate accepts only the configured origin.
        public CorsPolicy RestrictedOrigin()
        {
            var builder = new CorsPolicyBuilder();
            builder.SetIsOriginAllowed(origin => true);
            builder.SetIsOriginAllowed(origin => origin == "https://app.example.com");
            builder.AllowCredentials();
            return builder.Build();
        }

        // An override on only one branch does not change the effective policy on every path.
        public CorsPolicy ConditionalCredentialsOverride(bool disableCredentials)
        {
            var builder = new CorsPolicyBuilder().AllowAnyOrigin();
            builder.AllowCredentials(); // $ Alert
            if (disableCredentials)
            {
                builder.DisallowCredentials();
            }
            return builder.Build();
        }

        // Safe: two different builders.
        public void DifferentBuilders()
        {
            var anyOrigin = new CorsPolicyBuilder().AllowAnyOrigin();
            var trusted = new CorsPolicyBuilder("https://app.example.com").AllowCredentials();
        }
    }
}
