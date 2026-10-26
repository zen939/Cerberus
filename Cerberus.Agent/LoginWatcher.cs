using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 監看 Windows 安全性事件日誌，偵測異常登入並發告警：
///   4625 登入失敗（累積達門檻 → 疑似暴力破解）
///   4624 LogonType=10 遠端桌面（RDP）成功登入
///   4740 帳號鎖定
/// 讀 Security 日誌需 SYSTEM 權限（服務身分即可）。
/// </summary>
public sealed class LoginWatcher : BackgroundService
{
    // 只訂閱關心的事件；4624 僅限 RDP（LogonType=10），避免被大量網路/服務登入淹沒
    private const string Query =
        "*[System[(EventID=4625) or (EventID=4740)]] or " +
        "(*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']])";

    private readonly record struct FailKey(string Account);

    private readonly ConcurrentDictionary<FailKey, List<DateTime>> _failures = new();
    private readonly ConcurrentDictionary<FailKey, DateTime> _cooldown = new();

    private readonly AlertQueue _alerts;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<LoginWatcher> _logger;
    private EventLogWatcher? _watcher;

    public LoginWatcher(AlertQueue alerts, IOptionsMonitor<CerberusOptions> options, ILogger<LoginWatcher> logger)
    {
        _alerts = alerts;
        _options = options;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.CurrentValue.WatchLogons)
            return Task.CompletedTask;

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, Query);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            _logger.LogInformation("登入監看已啟用");
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            // 非 SYSTEM / 無安全性日誌存取權（例如開發偵錯）時停用
            _logger.LogWarning(ex, "無法訂閱安全性事件日誌，登入監看停用");
        }

        stoppingToken.Register(() =>
        {
            if (_watcher is not null)
            {
                _watcher.Enabled = false;
                _watcher.Dispose();
            }
        });
        return Task.CompletedTask;
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null)
            return;

        try
        {
            using var record = e.EventRecord;
            var data = ParseEventData(record.ToXml());
            switch (record.Id)
            {
                case 4625: HandleFailure(data); break;
                case 4624: HandleRemoteLogon(data); break;
                case 4740: HandleLockout(data); break;
            }
        }
        catch (Exception ex) when (ex is EventLogException or System.Xml.XmlException)
        {
            _logger.LogDebug(ex, "解析登入事件失敗");
        }
    }

    private void HandleFailure(IReadOnlyDictionary<string, string> d)
    {
        var account = Account(d);
        var key = new FailKey(account);
        var window = TimeSpan.FromMinutes(Math.Max(1, _options.CurrentValue.FailedLogonWindowMinutes));
        var now = DateTime.UtcNow;

        // 告警後冷卻一個時間窗，避免同一波攻擊連續洗頻
        if (_cooldown.TryGetValue(key, out var until) && now < until)
            return;

        var list = _failures.GetOrAdd(key, _ => []);
        lock (list)
        {
            list.Add(now);
            list.RemoveAll(t => now - t > window);

            if (list.Count < _options.CurrentValue.FailedLogonThreshold)
                return;

            list.Clear();
        }
        _cooldown[key] = now + window;

        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = AlertTypes.LogonFailureBurst,
            Details = $"疑似暴力破解：帳號「{account}」於 {window.TotalMinutes:0} 分鐘內登入失敗達門檻。" +
                      $"來源 IP={d.GetValueOrDefault("IpAddress", "?")}，來源主機={d.GetValueOrDefault("WorkstationName", "?")}",
            Mode = _options.CurrentValue.Mode
        });
    }

    private void HandleRemoteLogon(IReadOnlyDictionary<string, string> d)
    {
        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = AlertTypes.RemoteLogon,
            Details = $"偵測到遠端桌面（RDP）登入：帳號「{Account(d)}」，" +
                      $"來源 IP={d.GetValueOrDefault("IpAddress", "?")}，來源主機={d.GetValueOrDefault("WorkstationName", "?")}",
            Mode = _options.CurrentValue.Mode
        });
    }

    private void HandleLockout(IReadOnlyDictionary<string, string> d)
    {
        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = AlertTypes.AccountLockout,
            Details = $"帳號遭鎖定：「{d.GetValueOrDefault("TargetUserName", "?")}」" +
                      $"（來源主機={d.GetValueOrDefault("TargetDomainName", "?")}）",
            Mode = _options.CurrentValue.Mode
        });
    }

    private static string Account(IReadOnlyDictionary<string, string> d)
    {
        var user = d.GetValueOrDefault("TargetUserName", "?");
        var domain = d.GetValueOrDefault("TargetDomainName", string.Empty);
        return string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}";
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        foreach (var data in doc.Descendants(ns + "Data"))
        {
            var name = data.Attribute("Name")?.Value;
            if (!string.IsNullOrEmpty(name))
                result[name] = data.Value;
        }
        return result;
    }
}
