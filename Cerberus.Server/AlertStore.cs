using Cerberus.Shared;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>
/// 以 SQLite 持久化告警（稽核軌跡），Server 重啟後仍保留。
/// 低寫入量，單一連線加鎖即可；啟用 WAL 提升併發讀取。
/// </summary>
public sealed class AlertStore : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private readonly int _retention;
    private readonly ILogger<AlertStore> _logger;

    public AlertStore(IOptions<ServerOptions> options, ILogger<AlertStore> logger)
    {
        _logger = logger;
        _retention = Math.Max(1000, options.Value.AlertRetention);

        var path = options.Value.DbPath;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        _conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        _conn.Open();

        Execute("PRAGMA journal_mode=WAL;");
        Execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                id        TEXT NOT NULL,
                ts        TEXT NOT NULL,
                host      TEXT,
                type      TEXT,
                json      TEXT NOT NULL
            );
            """);
        Execute("CREATE INDEX IF NOT EXISTS ix_alerts_host ON alerts(host);");

        _logger.LogInformation("告警資料庫：{Path}", Path.GetFullPath(path));
    }

    public void Add(AlertMessage alert)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(alert, CerberusJson.Options);
        lock (_gate)
        {
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO alerts (id, ts, host, type, json) VALUES ($id, $ts, $host, $type, $json);";
                cmd.Parameters.AddWithValue("$id", alert.Id);
                cmd.Parameters.AddWithValue("$ts", alert.Timestamp.ToString("o"));
                cmd.Parameters.AddWithValue("$host", (object?)alert.HostName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$type", (object?)alert.Type ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$json", json);
                cmd.ExecuteNonQuery();
            }

            // 超過保留上限時刪最舊
            using (var trim = _conn.CreateCommand())
            {
                trim.CommandText =
                    "DELETE FROM alerts WHERE seq <= (SELECT MAX(seq) FROM alerts) - $keep;";
                trim.Parameters.AddWithValue("$keep", _retention);
                trim.ExecuteNonQuery();
            }
        }
    }

    public IReadOnlyList<AlertMessage> Recent(int take = 100)
    {
        take = Math.Clamp(take, 1, 1000);
        var result = new List<AlertMessage>(take);
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT json FROM alerts ORDER BY seq DESC LIMIT $take;";
            cmd.Parameters.AddWithValue("$take", take);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                try
                {
                    var alert = System.Text.Json.JsonSerializer.Deserialize<AlertMessage>(reader.GetString(0), CerberusJson.Options);
                    if (alert is not null)
                        result.Add(alert);
                }
                catch (System.Text.Json.JsonException) { }
            }
        }
        return result;
    }

    private void Execute(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _conn.Dispose();
}
