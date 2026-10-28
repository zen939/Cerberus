using System.Collections.Concurrent;
using Cerberus.Shared;

namespace Cerberus.Server;

public sealed record HostState(
    string HostName,
    string? UserName,
    DateTimeOffset LastSeen,
    string AgentVersion,
    EnforcementMode Mode,
    bool Online,
    string? OsVersion = null);

/// <summary>記錄各主機最後心跳時間與線上狀態（記憶體即可，重啟後由心跳重建）。</summary>
public sealed class HostRegistry
{
    private readonly ConcurrentDictionary<string, HostState> _hosts = new(StringComparer.OrdinalIgnoreCase);

    /// <returns>true 表示該主機先前為離線狀態、此次心跳為恢復。</returns>
    public bool Update(HeartbeatMessage hb)
    {
        bool wasOffline = _hosts.TryGetValue(hb.HostName, out var existing) && !existing.Online;
        _hosts.AddOrUpdate(hb.HostName,
            _ => new HostState(hb.HostName, hb.UserName, DateTimeOffset.UtcNow, hb.AgentVersion, hb.Mode, true, hb.OsVersion),
            (_, prev) => prev with
            {
                UserName = hb.UserName,
                LastSeen = DateTimeOffset.UtcNow,
                AgentVersion = hb.AgentVersion,
                Mode = hb.Mode,
                Online = true,
                OsVersion = hb.OsVersion ?? prev.OsVersion
            });
        return wasOffline;
    }

    public bool TrySetOffline(string hostName, out HostState? state)
    {
        state = null;
        if (_hosts.TryGetValue(hostName, out var prev) && prev.Online)
        {
            state = prev with { Online = false };
            _hosts[hostName] = state;
            return true;
        }
        return false;
    }

    public IReadOnlyCollection<HostState> Snapshot() => _hosts.Values.ToList();
}
