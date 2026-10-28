using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 定時取回 Server 的集中管理設定（模式、白名單），有變更才寫回本機 cerberus.json，
/// 透過既有熱重載生效——各工作者無需改動即讀到新值。
/// </summary>
public sealed class ConfigSyncWorker : BackgroundService
{
    private readonly ServerClient _server;
    private readonly AgentPaths _paths;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<ConfigSyncWorker> _logger;

    public ConfigSyncWorker(ServerClient server, AgentPaths paths,
        IOptionsMonitor<CerberusOptions> options, ILogger<ConfigSyncWorker> logger)
    {
        _server = server;
        _paths = paths;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var json = await _server.GetAsync("api/managed-config", stoppingToken);
                if (!string.IsNullOrEmpty(json))
                {
                    var managed = JsonSerializer.Deserialize<ManagedConfig>(json, CerberusJson.Options);
                    if (managed is not null)
                        Apply(managed);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "同步集中設定失敗");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
            catch (OperationCanceledException) { return; }
        }
    }

    private void Apply(ManagedConfig managed)
    {
        var current = _options.CurrentValue;
        bool changed = false;

        // 僅在與本機現值不同時才寫入，避免反覆改檔觸發重載
        if (managed.Mode is { } mode && mode != current.Mode)
            changed = true;
        if (managed.AllowedHosts is { } hosts && !hosts.SequenceEqual(current.AllowedHosts))
            changed = true;

        if (!changed)
            return;

        try
        {
            var root = JsonNode.Parse(File.ReadAllText(_paths.ConfigFile));
            var c = root?["Cerberus"];
            if (c is null)
                return;

            if (managed.Mode is { } m)
                c["Mode"] = m.ToString();
            if (managed.AllowedHosts is { } ah)
                c["AllowedHosts"] = new JsonArray(ah.Select(h => JsonValue.Create(h)).ToArray());

            File.WriteAllText(_paths.ConfigFile,
                root!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            _logger.LogInformation("已套用集中設定下發：Mode={Mode}, AllowedHosts={Count}",
                managed.Mode, managed.AllowedHosts?.Count);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            _logger.LogWarning(ex, "寫入集中設定失敗");
        }
    }
}
