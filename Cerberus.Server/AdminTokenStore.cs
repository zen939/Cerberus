using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>後台可設定的 Admin Token（SQLite 持久化）。未設時由 ServerOptions.AdminToken 作為預設。</summary>
public sealed class AdminTokenStore : IDisposable
{
    private const string Key = "admin_token";
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

    public AdminTokenStore(IOptions<ServerOptions> options)
    {
        _conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = options.Value.DbPath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        _conn.Open();

        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public string? Get()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT v FROM settings WHERE k=$k;";
            cmd.Parameters.AddWithValue("$k", Key);
            var v = cmd.ExecuteScalar() as string;
            return string.IsNullOrEmpty(v) ? null : v;
        }
    }

    public void Set(string token)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "INSERT INTO settings (k, v) VALUES ($k, $v) ON CONFLICT(k) DO UPDATE SET v=$v;";
            cmd.Parameters.AddWithValue("$k", Key);
            cmd.Parameters.AddWithValue("$v", token);
            cmd.ExecuteNonQuery();
        }
    }

    public void Dispose() => _conn.Dispose();
}
