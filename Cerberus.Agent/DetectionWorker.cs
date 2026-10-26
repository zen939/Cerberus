using System.Collections.Concurrent;
using System.Diagnostics;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 偵測主迴圈：合併「程序啟動事件」與「連線表輪詢」兩路輸入，
/// 對每個候選 PID 比對特徵；命中依模式告警或處置。
/// 每個 PID 在其存活期間只處理一次，避免重複告警與重複 Kill。
/// </summary>
public sealed class DetectionWorker : BackgroundService
{
    private readonly ProcessInspector _inspector;
    private readonly Enforcer _enforcer;
    private readonly AlertQueue _alerts;
    private readonly PipeServer _pipe;
    private readonly ProcessStartWatcher _startWatcher;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<DetectionWorker> _logger;

    // key = PID；value = 該 PID 的啟動時間(Ticks)，PID 重用時會不同
    private readonly ConcurrentDictionary<int, long> _handled = new();

    public DetectionWorker(ProcessInspector inspector, Enforcer enforcer, AlertQueue alerts, PipeServer pipe,
        ProcessStartWatcher startWatcher, IOptionsMonitor<CerberusOptions> options, ILogger<DetectionWorker> logger)
    {
        _inspector = inspector;
        _enforcer = enforcer;
        _alerts = alerts;
        _pipe = pipe;
        _startWatcher = startWatcher;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _startWatcher.Start();
        var eventPump = Task.Run(() => PumpStartEventsAsync(stoppingToken), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                ScanConnectionTable();
                PruneHandled();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "連線表掃描失敗");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, _options.CurrentValue.ScanIntervalSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await eventPump;
    }

    private async Task PumpStartEventsAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var pid in _startWatcher.Started.ReadAllAsync(ct))
                Evaluate(pid, matchedPort: null, portProtocol: null);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void ScanConnectionTable()
    {
        var suspiciousPorts = _options.CurrentValue.Tools
            .SelectMany(t => t.Ports)
            .ToHashSet();

        foreach (var conn in ConnectionTable.Read())
        {
            int? port = null;
            if (suspiciousPorts.Contains(conn.LocalPort)) port = conn.LocalPort;
            else if (suspiciousPorts.Contains(conn.RemotePort)) port = conn.RemotePort;

            Evaluate(conn.Pid, port, port is null ? null : conn.Protocol);
        }
    }

    private void Evaluate(int pid, int? matchedPort, TransportProtocol? portProtocol)
    {
        if (pid <= 4)
            return;

        long startTicks = ProcessStartTicks(pid);
        if (startTicks == 0)
            return; // 程序已結束或無權存取

        // 同一 PID(且同啟動時間)只處理一次
        if (_handled.TryGetValue(pid, out var seen) && seen == startTicks)
            return;

        var imagePath = NativeMethods.GetProcessImagePath(pid);
        if (string.IsNullOrEmpty(imagePath))
            return;

        var processName = Path.GetFileNameWithoutExtension(imagePath);
        var hit = _inspector.Inspect(processName, imagePath);

        if (hit is null)
        {
            // 僅連接埠命中:記一次,只告警不處置(降低誤判)
            if (matchedPort is not null && _handled.TryAdd(pid, startTicks))
                ReportPortOnly(pid, imagePath, processName, matchedPort.Value, portProtocol);
            return;
        }

        if (!_handled.TryAdd(pid, startTicks))
            return;

        Handle(pid, imagePath, processName, hit);
    }

    private void Handle(int pid, string imagePath, string processName, DetectionHit hit)
    {
        var options = _options.CurrentValue;
        bool allowedHost = options.AllowedHosts.Contains(Environment.MachineName, StringComparer.OrdinalIgnoreCase);
        bool enforce = options.Mode == EnforcementMode.Enforce && !allowedHost;

        string details = $"偵測到 {hit.Tool.Name}:{hit.Evidence}";
        string enforcement = string.Empty;

        if (enforce)
        {
            enforcement = _enforcer.Enforce(pid, imagePath, hit.Tool);
            details += $"。處置:{enforcement}";
        }
        else if (allowedHost)
        {
            details += "。(白名單主機,僅記錄)";
        }

        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = AlertTypes.Detection,
            Details = details,
            ToolName = hit.Tool.Name,
            ProcessName = processName,
            ProcessId = pid,
            FilePath = imagePath,
            Mode = options.Mode,
            Enforced = enforce && enforcement.Length > 0
        });

        _pipe.Notify(SessionIdOf(pid), "偵測到未授權遠端工具", $"{hit.Tool.Name}（{processName}）");
    }

    private void ReportPortOnly(int pid, string imagePath, string processName, int port, TransportProtocol? protocol)
    {
        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = AlertTypes.PortOnly,
            Details = $"程序連線命中遠端工具專用埠 {protocol} {port}，但未命中簽章/特徵，僅記錄",
            ProcessName = processName,
            ProcessId = pid,
            FilePath = imagePath,
            Mode = _options.CurrentValue.Mode,
            Enforced = false
        });
    }

    private static long ProcessStartTicks(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.StartTime.ToUniversalTime().Ticks;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return 0;
        }
    }

    private static int? SessionIdOf(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.SessionId;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    // 移除已結束 PID 的紀錄,避免字典無限成長
    private void PruneHandled()
    {
        if (_handled.Count < 256)
            return;

        foreach (var pid in _handled.Keys)
        {
            if (ProcessStartTicks(pid) == 0)
                _handled.TryRemove(pid, out _);
        }
    }
}
