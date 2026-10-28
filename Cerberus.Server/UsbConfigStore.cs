using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>
/// 儲存全域 USB 管控設定（後台可管理，Agent 輪詢取回）。
/// 存於同一 SQLite 檔的 settings 表，Server 重啟後保留。
/// </summary>
public sealed class UsbConfigStore : IDisposable
{
    private const string Key = "usb";
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();

    public UsbConfigStore(IOptions<ServerOptions> options)
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

    public UsbConfig Get()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT v FROM settings WHERE k=$k;";
            cmd.Parameters.AddWithValue("$k", Key);
            if (cmd.ExecuteScalar() is string json)
            {
                try { return JsonSerializer.Deserialize<UsbConfig>(json, CerberusJson.Options) ?? new(); }
                catch (JsonException) { }
            }
            return new UsbConfig();
        }
    }

    public void Set(UsbConfig config)
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
