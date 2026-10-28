using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>
/// 持久化「已註冊主機」的專屬 HMAC 金鑰（SQLite）。
/// 註冊時為每台產生亂數金鑰；驗章時與設定檔 HostKeys 一併查詢。
/// </summary>
public sealed class EnrolledKeyStore : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

    public EnrolledKeyStore(IOptions<ServerOptions> options)
    {
        _conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = options.Value.DbPath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        _conn.Open();

        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS enrolled (
                host       TEXT PRIMARY KEY,
                key        TEXT NOT NULL,
                enrolledAt TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public string? GetKey(string host)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT key FROM enrolled WHERE host=$h;";
            cmd.Parameters.AddWithValue("$h", host);
            return cmd.ExecuteScalar() as string;
        }
    }

    /// <summary>取得既有金鑰，或為新主機產生並儲存（idempotent）。</summary>
    public string GetOrCreate(string host)
    {
        lock (_gate)
        {
            var existing = GetKeyNoLock(host);
            if (existing is not null)
                return existing;

            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "INSERT INTO enrolled (host, key, enrolledAt) VALUES ($h, $k, $t);";
            cmd.Parameters.AddWithValue("$h", host);
            cmd.Parameters.AddWithValue("$k", key);
            cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
            return key;
        }
    }

    public IReadOnlyList<string> EnrolledHosts()
    {
        lock (_gate)
        {
            var list = new List<string>();
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT host FROM enrolled ORDER BY host;";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                list.Add(reader.GetString(0));
            return list;
        }
    }

    private string? GetKeyNoLock(string host)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT key FROM enrolled WHERE host=$h;";
        cmd.Parameters.AddWithValue("$h", host);
        return cmd.ExecuteScalar() as string;
    }

    public void Dispose() => _conn.Dispose();
}
