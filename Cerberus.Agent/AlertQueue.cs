using System.Text.Json;
using Cerberus.Shared;

namespace Cerberus.Agent;

/// <summary>
/// 告警先寫入 %ProgramData%\Cerberus\queue 再背景送出，
/// 斷網期間的紀錄不會遺失，恢復連線後依時間順序補送。
/// 同時寫入 ILogger（Windows 服務模式下 Warning 以上會進 Event Log）。
/// </summary>
public sealed class AlertQueue : BackgroundService
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(15);
    private const int MaxQueuedFiles = 5000;

    private readonly string _queueDir;
    private readonly ServerClient _server;
    private readonly ILogger<AlertQueue> _logger;
    private readonly SemaphoreSlim _signal = new(0);
    private readonly SemaphoreSlim _flushLock = new(1, 1);

    public AlertQueue(AgentPaths paths, ServerClient server, ILogger<AlertQueue> logger)
    {
        _queueDir = paths.QueueDir;
        _server = server;
        _logger = logger;
        Directory.CreateDirectory(_queueDir);
    }

    public void Enqueue(AlertMessage alert)
    {
        _logger.LogWarning("[{Type}] {Details} (工具={Tool}, 程序={Process}, PID={Pid}, 路徑={Path}, 使用者={User}, 處置={Enforced})",
            alert.Type, alert.Details, alert.ToolName, alert.ProcessName, alert.ProcessId, alert.FilePath, alert.UserName, alert.Enforced);

        try
        {
            TrimQueue();
            // 檔名以時間開頭，排序即送出順序
            var fileName = $"{alert.Timestamp.UtcTicks:D19}_{alert.Id}.json";
            File.WriteAllText(Path.Combine(_queueDir, fileName), JsonSerializer.Serialize(alert, CerberusJson.Options));
        }
        catch (IOException ex)
        {
            _logger.LogError(ex, "寫入告警佇列失敗");
        }

        _signal.Release();
    }

    /// <summary>立即嘗試送出佇列中的告警，回傳是否全部送完。</summary>
    public async Task<bool> FlushAsync(CancellationToken ct)
    {
        await _flushLock.WaitAsync(ct);
        try
        {
            foreach (var file in Directory.EnumerateFiles(_queueDir, "*.json").Order(StringComparer.Ordinal))
            {
                string json;
                try { json = await File.ReadAllTextAsync(file, ct); }
                catch (IOException) { continue; }

                if (!await _server.PostAsync("api/alert", json, ct))
                    return false;

                File.Delete(file);
            }
            return true;
        }
        finally
        {
            _flushLock.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FlushAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "送出告警佇列失敗，稍後重試");
            }

            try { await _signal.WaitAsync(RetryInterval, stoppingToken); }
            catch (OperationCanceledException) { return; }
        }
    }

    // 長期斷線時避免無限累積，丟棄最舊的
    private void TrimQueue()
    {
        var files = Directory.GetFiles(_queueDir, "*.json");
        if (files.Length < MaxQueuedFiles)
            return;

        foreach (var old in files.Order(StringComparer.Ordinal).Take(files.Length - MaxQueuedFiles + 1))
            File.Delete(old);
    }
}
