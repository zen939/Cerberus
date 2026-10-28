using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 監看可移除儲存裝置（USB）接入，依政策處置並告警：
///   Audit    只告警
///   ReadOnly 強制唯讀（StorageDevicePolicies\WriteProtect=1）
///   Block    非白名單裝置卸載、禁止存取
/// 另可於接入時自動以 Defender 掃描該磁碟。
/// </summary>
public sealed class UsbWatcher : BackgroundService
{
    private const string WriteProtectKey = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";

    private readonly UsbConfigProvider _config;
    private readonly AlertQueue _alerts;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<UsbWatcher> _logger;
    private ManagementEventWatcher? _watcher;

    public UsbWatcher(UsbConfigProvider config, AlertQueue alerts,
        IOptionsMonitor<CerberusOptions> options, ILogger<UsbWatcher> logger)
    {
        _config = config;
        _alerts = alerts;
        _options = options;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // EventType 2 = 裝置抵達（磁碟掛載）
            _watcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"));
            _watcher.EventArrived += OnVolumeArrived;
            _watcher.Start();
            _logger.LogInformation("USB 監看已啟用");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "無法訂閱磁碟事件，USB 監看停用");
        }

        stoppingToken.Register(() =>
        {
            try { _watcher?.Stop(); } catch (ManagementException) { }
            _watcher?.Dispose();
        });
        return Task.CompletedTask;
    }

    private void OnVolumeArrived(object sender, EventArrivedEventArgs e)
    {
        var drive = e.NewEvent["DriveName"] as string; // 例如 "E:"
        if (string.IsNullOrEmpty(drive))
            return;

        try { Handle(drive); }
        catch (Exception ex) when (ex is ManagementException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "處理 USB 接入失敗 {Drive}", drive);
        }
    }

    private void Handle(string drive)
    {
        if (!UsbDevices.IsRemovable(drive))
            return; // 只管可移除儲存，固定硬碟/光碟不處理

        var info = UsbDevices.FindByDrive(drive);
        var cfg = _config.Current;
        var serial = info?.Serial ?? "UNKNOWN";
        var allowed = cfg.Allowlist.Contains(serial, StringComparer.OrdinalIgnoreCase);
        var desc = info is null ? drive : $"{drive} {info.Model}（序號 {serial}）";

        string action;
        bool blocked = false;

        switch (cfg.Policy)
        {
            case UsbPolicy.Block when !allowed:
                blocked = Dismount(drive);
                action = blocked ? "非白名單，已卸載禁止存取" : "非白名單，卸載失敗";
                break;
            case UsbPolicy.ReadOnly when !allowed:
                SetWriteProtect(true);
                action = "已套用唯讀";
                break;
            default:
                action = allowed ? "白名單，允許" : "僅記錄（Audit）";
                break;
        }

        _alerts.Enqueue(new AlertMessage
        {
            HostName = Environment.MachineName,
            UserName = SessionUser.ForConsole(),
            Type = blocked ? AlertTypes.UsbBlocked : AlertTypes.UsbInserted,
            Details = $"USB 可移除裝置接入：{desc}。政策={cfg.Policy}，處置：{action}",
            ToolName = info?.Model,
            FilePath = serial,
            Mode = _options.CurrentValue.Mode,
            Enforced = blocked || (cfg.Policy == UsbPolicy.ReadOnly && !allowed)
        });

        if (!blocked && cfg.ScanOnInsert)
            ScanDrive(drive);
    }

    private void SetWriteProtect(bool on)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(WriteProtectKey);
            key.SetValue("WriteProtect", on ? 1 : 0, RegistryValueKind.DWord);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            _logger.LogWarning(ex, "設定 WriteProtect 失敗");
        }
    }

    // 以 mountvol /p 卸載並離線，使磁碟內容無法存取
    private bool Dismount(string drive)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "mountvol.exe",
                Arguments = $"{drive} /p",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (proc is null)
                return false;
            proc.WaitForExit(15000);
            return proc.HasExited && proc.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _logger.LogWarning(ex, "卸載 {Drive} 失敗", drive);
            return false;
        }
    }

    private void ScanDrive(string drive)
    {
        var exe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(exe))
            return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"-Scan -ScanType 3 -File {drive}\\",
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception)
        {
            _logger.LogDebug(ex, "啟動 USB 掃描失敗");
        }
    }
}
