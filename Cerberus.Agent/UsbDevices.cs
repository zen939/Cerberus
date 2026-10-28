using System.Management;

namespace Cerberus.Agent;

public sealed record UsbDiskInfo(string Model, string Serial, string PnpDeviceId, string InterfaceType);

/// <summary>
/// 以 WMI 關聯查詢，由磁碟機代號（如 E:）找出背後實體磁碟的序號/型號/介面，
/// 用於 USB 隨身碟的識別與白名單比對。
/// </summary>
public static class UsbDevices
{
    /// <summary>該磁碟機代號是否為「可移除」磁碟（DriveType=2）。</summary>
    public static bool IsRemovable(string drive)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT DriveType FROM Win32_LogicalDisk WHERE DeviceID='{Escape(drive)}'");
            foreach (ManagementObject d in searcher.Get())
            {
                using (d)
                    return d["DriveType"] is uint t && t == 2;
            }
        }
        catch (ManagementException) { }
        return false;
    }

    /// <summary>由磁碟機代號回溯到實體磁碟資訊（LogicalDisk → Partition → DiskDrive）。</summary>
    public static UsbDiskInfo? FindByDrive(string drive)
    {
        try
        {
            foreach (var partition in Associators(
                $"Win32_LogicalDisk.DeviceID='{Escape(drive)}'", "Win32_LogicalDiskToPartition"))
            {
                var partId = partition["DeviceID"] as string;
                partition.Dispose();
                if (partId is null)
                    continue;

                foreach (var disk in Associators(
                    $"Win32_DiskPartition.DeviceID='{Escape(partId)}'", "Win32_DiskDriveToDiskPartition"))
                {
                    using (disk)
                    {
                        return new UsbDiskInfo(
                            Model: (disk["Model"] as string ?? "").Trim(),
                            Serial: NormalizeSerial(disk["SerialNumber"] as string, disk["PNPDeviceID"] as string),
                            PnpDeviceId: disk["PNPDeviceID"] as string ?? "",
                            InterfaceType: disk["InterfaceType"] as string ?? "");
                    }
                }
            }
        }
        catch (ManagementException) { }
        return null;
    }

    private static IEnumerable<ManagementObject> Associators(string path, string assocClass)
    {
        using var searcher = new ManagementObjectSearcher(
            new ObjectQuery($"ASSOCIATORS OF {{{path}}} WHERE AssocClass={assocClass}"));
        foreach (ManagementObject o in searcher.Get())
            yield return o;
    }

    // 序號優先用 SerialNumber，否則從 PNPDeviceID 末段取得（USB 裝置實例 ID）
    private static string NormalizeSerial(string? serial, string? pnp)
    {
        serial = serial?.Trim();
        if (!string.IsNullOrEmpty(serial))
            return serial;

        if (!string.IsNullOrEmpty(pnp))
        {
            var parts = pnp.Split('\\');
            if (parts.Length > 0)
                return parts[^1];
        }
        return "UNKNOWN";
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'");
}
