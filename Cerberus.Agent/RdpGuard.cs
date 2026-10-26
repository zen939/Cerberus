using Microsoft.Extensions.Options;
using Microsoft.Win32;
using Cerberus.Shared;

namespace Cerberus.Agent;

/// <summary>
/// 巡檢本機遠端桌面開關 fDenyTSConnections。
/// 1 = 停用 RDP（預設安全值）；0 = 已開啟。
/// Audit 模式僅告警；Enforce 模式改回 1。
/// </summary>
public sealed class RdpGuard : BackgroundService
{
    private const string KeyPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string ValueName = "fDenyTSConnections";

    private readonly AlertQueue _alerts;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<RdpGuard> _logger;

    public RdpGuard(AlertQueue alerts, IOptionsMonitor<CerberusOptions> options, ILogger<RdpGuard> logger)
    {
        _alerts = alerts;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var options = _options.CurrentValue;
            if (options.GuardRdp)
                Check(options);

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, options.RdpCheckIntervalSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void Check(CerberusOptions options)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: options.Mode == EnforcementMode.Enforce);
            if (key?.GetValue(ValueName) is not int value || value != 0)
                return; // 未開啟或鍵不存在

            bool allowedHost = options.AllowedHosts.Contains(Environment.MachineName, StringComparer.OrdinalIgnoreCase);
            bool fixedIt = false;

            if (options.Mode == EnforcementMode.Enforce && !allowedHost)
            {
                key!.SetValue(ValueName, 1, RegistryValueKind.DWord);
                fixedIt = true;
            }

            _alerts.Enqueue(new AlertMessage
            {
                HostName = Environment.MachineName,
                UserName = SessionUser.ForConsole(),
                Type = AlertTypes.RdpEnabled,
                Details = fixedIt
                    ? "偵測到本機遠端桌面已被開啟，已改回停用"
                    : "偵測到本機遠端桌面已被開啟（fDenyTSConnections=0）",
                Mode = options.Mode,
                Enforced = fixedIt
            });
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            _logger.LogWarning(ex, "巡檢 RDP 設定失敗");
        }
    }
}
