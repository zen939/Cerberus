using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>後台可管理的 Webhook 網址（SQLite 持久化）。未設定時由 ServerOptions.WebhookUrl 作為預設。</summary>
public sealed class WebhookSettingsStore : IDisposable
{
    private const string Key = "webhook_url";
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

    public WebhookSettingsStore(IOptions<ServerOptions> options)
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

    /// <summary>取得已設定的網址；未設定回傳 null。</summary>
    public string? Get()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT v FROM settings WHERE k=$k;";
            cmd.Parameters.AddWithValue("$k", Key);
            return cmd.ExecuteScalar() as string;
        }
    }

    public void Set(string? url)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "INSERT INTO settings (k, v) VALUES ($k, $v) ON CONFLICT(k) DO UPDATE SET v=$v;";
            cmd.Parameters.AddWithValue("$k", Key);
            cmd.Parameters.AddWithValue("$v", url ?? string.Empty);
            cmd.ExecuteNonQuery();
        }
    }

    public void Dispose() => _conn.Dispose();
}
