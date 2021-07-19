using Identity.Infrastructure.DbContexts;
using Identity.STS.Configuration.Database;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.STS.Helpers
{
    public static class DbMigrationHelpers
    {
        public static async Task ApplyDbMigrationsAsync(IHost host, DatabaseMigrationsConfiguration databaseMigrationsConfiguration)
        {
            using (var serviceScope = host.Services.CreateScope())
            {
                var services = serviceScope.ServiceProvider;

                if ((databaseMigrationsConfiguration != null && databaseMigrationsConfiguration.ApplyDatabaseMigrations))
                {
                    await EnsureDatabasesMigratedAsync(services);
                }
            }
        }


        public static async Task EnsureDatabasesMigratedAsync(IServiceProvider services)
        {
            using (var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                using (var context = scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>())
                {
                    await context.Database.MigrateAsync();
                }

                using (var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>())
                {
                    await context.Database.MigrateAsync();
                }

                using (var context = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>())
                {
                    await context.Database.MigrateAsync();
                }

                //using (var context = scope.ServiceProvider.GetRequiredService<TLogDbContext>())
                //{
                //    await context.Database.MigrateAsync();
                //}

                //using (var context = scope.ServiceProvider.GetRequiredService<TAuditLogDbContext>())
                //{
                //    await context.Database.MigrateAsync();
                //}

                //using (var context = scope.ServiceProvider.GetRequiredService<TDataProtectionDbContext>())
                //{
                //    await context.Database.MigrateAsync();
                //}
            }
        }

    }
}
