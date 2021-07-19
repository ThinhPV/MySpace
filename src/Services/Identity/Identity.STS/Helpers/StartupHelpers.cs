using Identity.Core.Entities.Identity;
using Identity.Infrastructure.DbContexts;
using Identity.STS.Configuration;
using Identity.STS.Configuration.Constants;
using Identity.STS.Configuration.Identity;
using Identity.STS.Helpers.Localization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Globalization;
using System.Linq;

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

            var authenticationBuilder = services.AddAuthentication();
            AddExternalProviders(authenticationBuilder, configuration);

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


        private static void AddExternalProviders(AuthenticationBuilder authenticationBuilder,
            IConfiguration configuration)
        {
            var externalProviderConfiguration = configuration.GetSection(nameof(ExternalProvidersConfiguration)).Get<ExternalProvidersConfiguration>();

            if (externalProviderConfiguration.UseGitHubProvider)
            {
                authenticationBuilder.AddGitHub(options =>
                {
                    options.ClientId = externalProviderConfiguration.GitHubClientId;
                    options.ClientSecret = externalProviderConfiguration.GitHubClientSecret;
                    options.CallbackPath = externalProviderConfiguration.GitHubCallbackPath;
                    options.Scope.Add("user:email");
                });
            }

            //if (externalProviderConfiguration.UseAzureAdProvider)
            //{
            //    authenticationBuilder.AddMicrosoftIdentityWebApp(options =>
            //    {
            //        options.ClientSecret = externalProviderConfiguration.AzureAdSecret;
            //        options.ClientId = externalProviderConfiguration.AzureAdClientId;
            //        options.TenantId = externalProviderConfiguration.AzureAdTenantId;
            //        options.Instance = externalProviderConfiguration.AzureInstance;
            //        options.Domain = externalProviderConfiguration.AzureDomain;
            //        options.CallbackPath = externalProviderConfiguration.AzureAdCallbackPath;
            //    });
            //}
        }
    }
}
