using System.Reflection;
using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>定時送心跳，Server 端 3 分鐘收不到即判定失聯（Dead Man's Snitch）。</summary>
public sealed class HeartbeatWorker : BackgroundService
{
    private static readonly string AgentVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";

    private readonly ServerClient _server;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<HeartbeatWorker> _logger;

    public HeartbeatWorker(ServerClient server, IOptionsMonitor<CerberusOptions> options, ILogger<HeartbeatWorker> logger)
    {
        _server = server;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_server.IsConfigured)
            _logger.LogWarning("未設定 ServerUrl / HostKey，心跳與告警將只保留在本機");

        while (!stoppingToken.IsCancellationRequested)
        {
            var options = _options.CurrentValue;
            var heartbeat = new HeartbeatMessage
            {
                HostName = Environment.MachineName,
                UserName = SessionUser.ForConsole(),
                AgentVersion = AgentVersion,
                Mode = options.Mode
            };

            if (!await _server.PostAsync("api/heartbeat", JsonSerializer.Serialize(heartbeat, CerberusJson.Options), stoppingToken))
                _logger.LogDebug("心跳送出失敗");

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, options.HeartbeatIntervalSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
