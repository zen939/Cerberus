using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 提供目前生效的 USB 管控設定：定時向 Server 取回（後台可管理），
/// 取不到時退回本機 cerberus.json 的 Usb 設定。
/// </summary>
public sealed class UsbConfigProvider : BackgroundService
{
    private readonly ServerClient _server;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<UsbConfigProvider> _logger;
    private volatile UsbConfig? _fromServer;

    public UsbConfigProvider(ServerClient server, IOptionsMonitor<CerberusOptions> options, ILogger<UsbConfigProvider> logger)
    {
        _server = server;
        _options = options;
        _logger = logger;
    }

    /// <summary>Server 下發的設定優先，否則用本機預設。</summary>
    public UsbConfig Current => _fromServer ?? _options.CurrentValue.Usb;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var json = await _server.GetAsync("api/usb-policy", stoppingToken);
                if (!string.IsNullOrEmpty(json))
                {
                    var cfg = JsonSerializer.Deserialize<UsbConfig>(json, CerberusJson.Options);
                    if (cfg is not null)
                        _fromServer = cfg;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "取得 USB 政策失敗，沿用現有設定");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, _options.CurrentValue.UsbPolicyPollSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
