using System.Management;
using System.Threading.Channels;

namespace Cerberus.Agent;

/// <summary>
/// 訂閱 WMI Win32_ProcessStartTrace（需 SYSTEM / 系統管理員），
/// 程序一啟動就丟進佇列給 DetectionWorker 即時檢查，不必等下一輪輪詢。
/// </summary>
public sealed class ProcessStartWatcher : IDisposable
{
    private readonly Channel<int> _started = Channel.CreateBounded<int>(
        new BoundedChannelOptions(1024) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly ILogger<ProcessStartWatcher> _logger;
    private ManagementEventWatcher? _watcher;

    public ProcessStartWatcher(ILogger<ProcessStartWatcher> logger) => _logger = logger;

    public ChannelReader<int> Started => _started.Reader;

    public void Start()
    {
        try
        {
            _watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID FROM Win32_ProcessStartTrace"));
            _watcher.EventArrived += (_, e) =>
            {
                if (e.NewEvent["ProcessID"] is uint pid)
                    _started.Writer.TryWrite((int)pid);
            };
            _watcher.Start();
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // 非系統管理員執行（例如開發偵錯）時只靠輪詢
            _logger.LogWarning(ex, "無法訂閱程序啟動事件，改為僅輪詢偵測");
            _watcher?.Dispose();
            _watcher = null;
        }
    }

    public void Dispose()
    {
        try { _watcher?.Stop(); } catch (ManagementException) { }
        _watcher?.Dispose();
    }
}
