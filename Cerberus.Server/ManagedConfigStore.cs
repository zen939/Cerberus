using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>集中管理設定（全域）的持久化儲存（SQLite settings 表）。</summary>
public sealed class ManagedConfigStore : IDisposable
{
    private const string Key = "managed";
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

    public ManagedConfigStore(IOptions<ServerOptions> options)
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

    public ManagedConfig Get()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT v FROM settings WHERE k=$k;";
            cmd.Parameters.AddWithValue("$k", Key);
            if (cmd.ExecuteScalar() is string json)
            {
                try { return JsonSerializer.Deserialize<ManagedConfig>(json, CerberusJson.Options) ?? new(); }
                catch (JsonException) { }
            }
            return new ManagedConfig();
        }
    }

    public void Set(ManagedConfig config)
    {
        var json = JsonSerializer.Serialize(config, CerberusJson.Options);
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "INSERT INTO settings (k, v) VALUES ($k, $v) ON CONFLICT(k) DO UPDATE SET v=$v;";
            cmd.Parameters.AddWithValue("$k", Key);
            cmd.Parameters.AddWithValue("$v", json);
            cmd.ExecuteNonQuery();
        }
    }

    public void Dispose() => _conn.Dispose();
}
