// Minimal stubs for the framework types used by the CorsAllowCredentialsAnyOrigin tests.

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
    public class CorsPolicy { }

    public class CorsPolicyBuilder
    {
        public CorsPolicyBuilder(params string[] origins) { }
        public CorsPolicyBuilder AllowAnyOrigin() => this;
        public CorsPolicyBuilder AllowAnyMethod() => this;
        public CorsPolicyBuilder AllowAnyHeader() => this;
        public CorsPolicyBuilder AllowCredentials() => this;
        public CorsPolicyBuilder DisallowCredentials() => this;
        public CorsPolicyBuilder WithOrigins(params string[] origins) => this;
        public CorsPolicyBuilder SetIsOriginAllowed(System.Func<string, bool> isOriginAllowed) => this;
        public CorsPolicy Build() => null;
    }

    public class CorsOptions
    {
        public void AddPolicy(string name, System.Action<CorsPolicyBuilder> configurePolicy) { }
        public void AddPolicy(string name, CorsPolicy policy) { }
        public void AddDefaultPolicy(System.Action<CorsPolicyBuilder> configurePolicy) { }
    }
}

namespace Microsoft.Extensions.DependencyInjection
{
    public interface IServiceCollection { }

    public static class CorsServiceCollectionExtensions
    {
        public static IServiceCollection AddCors(this IServiceCollection services, System.Action<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions> setupAction) => services;
    }
}
