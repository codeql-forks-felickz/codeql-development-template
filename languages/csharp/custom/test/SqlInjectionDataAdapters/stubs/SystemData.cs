// Minimal stubs modelled on System.Data / System.Data.Common public API signatures.
namespace System.Data
{
    public class DataSet { }

    public interface IDataReader : IDisposable
    {
        bool Read();
    }

    public interface IDbCommand : IDisposable
    {
        string CommandText { get; set; }
        int ExecuteNonQuery();
        IDataReader ExecuteReader();
    }
}

namespace System.Data.Common
{
    public abstract class DbDataAdapter
    {
        public int Fill(System.Data.DataSet dataSet) => throw null;
        public int Fill(System.Data.DataSet dataSet, string srcTable) => throw null;
    }
}
