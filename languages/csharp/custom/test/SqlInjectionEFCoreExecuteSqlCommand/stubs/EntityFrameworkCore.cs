// Minimal stubs modelled on Microsoft.EntityFrameworkCore 2.1 public API signatures.
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.EntityFrameworkCore
{
    public struct RawSqlString
    {
        public RawSqlString(string s) => throw null;
        public static implicit operator RawSqlString(string s) => throw null;
        public static implicit operator RawSqlString(FormattableString fs) => throw null;
        public string Format => throw null;
    }

    public class DbContext
    {
        public Infrastructure.DatabaseFacade Database => throw null;
    }

    public static class RelationalDatabaseFacadeExtensions
    {
        // EF Core 2.x
        public static int ExecuteSqlCommand(this Infrastructure.DatabaseFacade databaseFacade, RawSqlString sql, params object[] parameters) => throw null;
        public static int ExecuteSqlCommand(this Infrastructure.DatabaseFacade databaseFacade, FormattableString sql) => throw null;
        public static int ExecuteSqlCommand(this Infrastructure.DatabaseFacade databaseFacade, RawSqlString sql, IEnumerable<object> parameters) => throw null;
        public static Task<int> ExecuteSqlCommandAsync(this Infrastructure.DatabaseFacade databaseFacade, FormattableString sql, CancellationToken cancellationToken = default(CancellationToken)) => throw null;
        public static Task<int> ExecuteSqlCommandAsync(this Infrastructure.DatabaseFacade databaseFacade, RawSqlString sql, CancellationToken cancellationToken = default(CancellationToken)) => throw null;
        public static Task<int> ExecuteSqlCommandAsync(this Infrastructure.DatabaseFacade databaseFacade, RawSqlString sql, params object[] parameters) => throw null;
        public static Task<int> ExecuteSqlCommandAsync(this Infrastructure.DatabaseFacade databaseFacade, RawSqlString sql, IEnumerable<object> parameters, CancellationToken cancellationToken = default(CancellationToken)) => throw null;

        // EF Core 3.0+
        public static int ExecuteSqlRaw(this Infrastructure.DatabaseFacade databaseFacade, string sql, params object[] parameters) => throw null;
        public static int ExecuteSqlInterpolated(this Infrastructure.DatabaseFacade databaseFacade, FormattableString sql) => throw null;
        public static Task<int> ExecuteSqlRawAsync(this Infrastructure.DatabaseFacade databaseFacade, string sql, params object[] parameters) => throw null;
        public static Task<int> ExecuteSqlInterpolatedAsync(this Infrastructure.DatabaseFacade databaseFacade, FormattableString sql, CancellationToken cancellationToken = default(CancellationToken)) => throw null;
    }
}

namespace Microsoft.EntityFrameworkCore.Infrastructure
{
    public class DatabaseFacade { }
}
