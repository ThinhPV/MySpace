using Identity.Core.Entities.Identity;
using Identity.Infrastructure.DbContexts;
using Identity.STS.Configuration;
using Identity.STS.Configuration.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace Identity.STS.Helpers
{
    public static class StartupHelpers
    {
        public static void AddAuthenticationServices(this IServiceCollection services, IConfiguration configuration)
        {
            var loginConfiguration = GetLoginConfiguration(configuration);
            var identityOptions = configuration.GetSection(nameof(IdentityOptions)).Get<IdentityOptions>();

            services
                .AddSingleton(loginConfiguration)
                .AddSingleton(identityOptions)
                //.AddScoped<UserResolver<UserIdentity>>()
                .AddIdentity<UserIdentity, IdentityRole>(options => configuration.GetSection(nameof(IdentityOptions)).Bind(options))
                .AddEntityFrameworkStores<IdentityDbContext>()
                .AddDefaultTokenProviders();
        }

        public static IIdentityServerBuilder RegisterIdentityServer(this IServiceCollection services, IConfiguration configuration)
        {
            var advancedConfiguration = configuration.GetSection(nameof(AdvancedConfiguration)).Get<AdvancedConfiguration>();

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                //if (!string.IsNullOrEmpty(advancedConfiguration.PublicOrigin))
                //{
                //    options.PublicOrigin = advancedConfiguration.PublicOrigin;
                //}

                if (!string.IsNullOrEmpty(advancedConfiguration.IssuerUri))
                {
                    options.IssuerUri = advancedConfiguration.IssuerUri;
                }
            })
            .AddConfigurationStore()
            .AddOperationalStore()
            .AddAspNetIdentity<UserIdentity>();

            builder.AddCustomSigningCredential(configuration);
            builder.AddCustomValidationKey(configuration);

            return builder;
        }

        /// <summary>
        /// Get configuration for login
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        private static LoginConfiguration GetLoginConfiguration(IConfiguration configuration)
        {
            var loginConfiguration = configuration.GetSection(nameof(LoginConfiguration)).Get<LoginConfiguration>();

            // Cannot load configuration - use default configuration values
            if (loginConfiguration == null)
            {
                return new LoginConfiguration();
            }

            return loginConfiguration;
        }

    }
}
