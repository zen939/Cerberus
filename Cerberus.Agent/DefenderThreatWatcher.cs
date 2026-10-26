using System.Management;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 定時讀取 Windows Defender 威脅紀錄，將新偵測（含即時防護自動攔截與各類掃描結果）
/// 轉為正式告警，走與遠端工具偵測相同的告警管線（面板 + Webhook）。
/// </summary>
public sealed class DefenderThreatWatcher : BackgroundService
{
    private readonly AlertQueue _alerts;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<DefenderThreatWatcher> _logger;

    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    // 只回報服務啟動後的新偵測，避免啟動時把歷史紀錄全部重送
    private DateTimeOffset _since = DateTimeOffset.UtcNow;

    public DefenderThreatWatcher(AlertQueue alerts, IOptionsMonitor<CerberusOptions> options,
        ILogger<DefenderThreatWatcher> logger)
    {
        _alerts = alerts;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 啟動時先把既有偵測記為已見（但不送），之後只送新的
        SeedSeen();

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_options.CurrentValue.ReportDefenderThreats)
            {
                try { Poll(); }
                catch (ManagementException ex) { _logger.LogDebug(ex, "讀取 Defender 威脅紀錄失敗"); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogWarning(ex, "威脅監看異常"); }
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(15, _options.CurrentValue.DefenderThreatPollSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void SeedSeen()
    {
        try
        {
            foreach (var t in DefenderThreats.Query())
                _seen.Add(t.DetectionId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "初始化 Defender 威脅清單失敗（可能非 Defender 環境），停用威脅監看");
        }
    }

    private void Poll()
    {
        foreach (var t in DefenderThreats.Query())
        {
            if (!_seen.Add(t.DetectionId))
                continue; // 已處理過

            if (t.DetectedAt < _since.AddMinutes(-5))
                continue; // 舊歷史紀錄，略過

            _alerts.Enqueue(new AlertMessage
            {
                HostName = Environment.MachineName,
                UserName = SessionUser.ForConsole(),
                Type = AlertTypes.MalwareDetected,
                Details = $"Defender 偵測到威脅「{t.ThreatName}」(嚴重度 {t.SeverityId})，處置：{t.ActionStatus}。影響：{t.Resources}",
                ToolName = t.ThreatName,
                FilePath = t.Resources,
                Mode = _options.CurrentValue.Mode,
                Enforced = t.ActionStatus is "已清除" or "已隔離" or "已移除" or "已封鎖"
            });
        }

        // 避免 _seen 無限成長
        if (_seen.Count > 5000)
        {
            _seen.Clear();
            SeedSeen();
        }
    }
}
