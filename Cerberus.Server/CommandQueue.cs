using System.Collections.Concurrent;
using Cerberus.Shared;

namespace Cerberus.Server;

/// <summary>
/// 每台主機的指令佇列（記憶體）。管理介面排入指令，Agent 輪詢取走並回報結果。
/// 重啟後清空（指令為即時性操作，不需持久化）。
/// </summary>
public sealed class CommandQueue
{
    private const int HistoryCap = 500;
    private readonly ConcurrentDictionary<string, ConcurrentQueue<string>> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CommandMessage> _all = new();

    public CommandMessage Enqueue(string hostName, CommandAction action, string? requestedBy)
    {
        var cmd = new CommandMessage { HostName = hostName, Action = action, RequestedBy = requestedBy };
        _all[cmd.Id] = cmd;
        _pending.GetOrAdd(hostName, _ => new ConcurrentQueue<string>()).Enqueue(cmd.Id);
        TrimHistory();
        return cmd;
    }

    /// <summary>取出某主機所有待處理指令並標記為 Dispatched。</summary>
    public List<CommandMessage> TakePending(string hostName)
    {
        var result = new List<CommandMessage>();
        if (!_pending.TryGetValue(hostName, out var queue))
            return result;

        while (queue.TryDequeue(out var id))
        {
            if (_all.TryGetValue(id, out var cmd) && cmd.Status == CommandStatus.Pending)
            {
                cmd.Status = CommandStatus.Dispatched;
                cmd.DispatchedAt = DateTimeOffset.UtcNow;
                result.Add(cmd);
            }
        }
        return result;
    }

    public bool Complete(CommandResult result)
    {
        if (!_all.TryGetValue(result.CommandId, out var cmd))
            return false;

        cmd.Status = result.Success ? CommandStatus.Completed : CommandStatus.Failed;
        cmd.Success = result.Success;
        cmd.Output = result.Output;
        cmd.CompletedAt = result.CompletedAt;
        return true;
    }

    public IReadOnlyList<CommandMessage> Recent(int take = 100) =>
        _all.Values.OrderByDescending(c => c.CreatedAt).Take(take).ToList();

    private void TrimHistory()
    {
        if (_all.Count <= HistoryCap)
            return;

        foreach (var old in _all.Values.OrderBy(c => c.CreatedAt)
                     .Take(_all.Count - HistoryCap)
                     .Where(c => c.Status is CommandStatus.Completed or CommandStatus.Failed))
        {
            _all.TryRemove(old.Id, out _);
        }
    }
}
