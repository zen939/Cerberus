using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 服務正常啟動 / 停止（OnStop、OnShutdown / Preshutdown）時送出告警。
/// 注意：遭 TerminateProcess 強制結束時不會觸發任何清理碼，
/// 該情境一律由 Server 端 3 分鐘失聯告警涵蓋。
/// </summary>
public sealed class LifecycleReporter : IHostedService
{
    private readonly AlertQueue _alerts;
    private readonly IOptionsMonitor<CerberusOptions> _options;

    public LifecycleReporter(AlertQueue alerts, IOptionsMonitor<CerberusOptions> options)
    {
        _alerts = alerts;
        _options = options;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        Report(AlertTypes.AgentStarted, $"Cerberus Agent 已啟動（模式：{_options.CurrentValue.Mode}）");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Report(AlertTypes.AgentStopped, "Cerberus Agent 正常停止或系統關機");
        return Task.CompletedTask;
    }

    private void Report(string type, string details) =>
        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = type,
            Details = details,
            Mode = _options.CurrentValue.Mode
        });
}
