using System.Collections.Concurrent;
using Cerberus.Shared;

namespace Cerberus.Server;

/// <summary>保留最近 N 筆告警供管理介面顯示（記憶體環狀緩衝，重啟後清空）。</summary>
public sealed class AlertStore
{
    private const int Capacity = 500;
    private readonly ConcurrentQueue<AlertMessage> _alerts = new();

    public void Add(AlertMessage alert)
    {
        _alerts.Enqueue(alert);
        while (_alerts.Count > Capacity && _alerts.TryDequeue(out _)) { }
    }

    public IReadOnlyList<AlertMessage> Recent(int take = 100) =>
        _alerts.Reverse().Take(take).ToList();
}
