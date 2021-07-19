using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.STS.Configuration.Database
{
	public class DatabaseMigrationsConfiguration
	{
		public bool ApplyDatabaseMigrations { get; set; } = true;

		public string ConfigurationDbMigrationsAssembly { get; set; }

		public string PersistedGrantDbMigrationsAssembly { get; set; }

		//public string AdminLogDbMigrationsAssembly { get; set; }

		public string IdentityDbMigrationsAssembly { get; set; }

		//public string AdminAuditLogDbMigrationsAssembly { get; set; }

		//public string DataProtectionDbMigrationsAssembly { get; set; }

		public void SetMigrationsAssemblies(string commonMigrationsAssembly)
		{
			//AdminAuditLogDbMigrationsAssembly = commonMigrationsAssembkkly;
			//AdminLogDbMigrationsAssembly = commonMigrationsAssembly;
			ConfigurationDbMigrationsAssembly = commonMigrationsAssembly;
			//DataProtectionDbMigrationsAssembly = commonMigrationsAssembly;
			IdentityDbMigrationsAssembly = commonMigrationsAssembly;
			PersistedGrantDbMigrationsAssembly = commonMigrationsAssembly;
		}
	}
}
