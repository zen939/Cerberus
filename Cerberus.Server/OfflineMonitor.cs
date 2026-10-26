using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>Dead Man's Snitch：定時檢查，超過門檻未收到心跳的主機主動告警。</summary>
public sealed class OfflineMonitor : BackgroundService
{
    private readonly HostRegistry _registry;
    private readonly WebhookForwarder _webhook;
    private readonly IOptionsMonitor<ServerOptions> _options;
    private readonly ILogger<OfflineMonitor> _logger;

    public OfflineMonitor(HostRegistry registry, WebhookForwarder webhook,
        IOptionsMonitor<ServerOptions> options, ILogger<OfflineMonitor> logger)
    {
        _registry = registry;
        _webhook = webhook;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var options = _options.CurrentValue;
            var threshold = TimeSpan.FromSeconds(options.OfflineThresholdSeconds);
            var now = DateTimeOffset.UtcNow;

            foreach (var host in _registry.Snapshot())
            {
                if (host.Online && now - host.LastSeen > threshold &&
                    _registry.TrySetOffline(host.HostName, out _))
                {
                    var msg = $"⚠️ 主機 {host.HostName} 監控中斷或異常離線" +
                              $"（最後心跳 {host.LastSeen.ToLocalTime():yyyy-MM-dd HH:mm:ss}，使用者 {host.UserName ?? "未知"}）";
                    _logger.LogWarning("{Message}", msg);
                    await _webhook.SendAsync(msg, stoppingToken);
                }
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(5, options.OfflineCheckIntervalSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
