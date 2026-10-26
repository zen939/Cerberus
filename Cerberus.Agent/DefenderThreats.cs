using System.Management;

namespace Cerberus.Agent;

public sealed record ThreatDetection(
    string DetectionId,
    string ThreatName,
    int SeverityId,
    DateTimeOffset DetectedAt,
    string Resources,
    string ActionStatus);

/// <summary>
/// 讀取 Windows Defender 威脅紀錄（WMI 命名空間 root\Microsoft\Windows\Defender）。
/// 以 MSFT_MpThreatDetection 取偵測事件，再以 MSFT_MpThreat 把 ThreatID 對應到病毒名稱。
/// 純查詢、唯讀。
/// </summary>
public static class DefenderThreats
{
    private const string Namespace = @"root\Microsoft\Windows\Defender";

    // CurrentThreatExecutionStatusID / ThreatStatusID 的常見值對應
    private static readonly Dictionary<int, string> StatusText = new()
    {
        [0] = "未知",
        [1] = "已偵測",
        [2] = "已清除",
        [3] = "已隔離",
        [4] = "已移除",
        [5] = "已允許",
        [6] = "已封鎖",
    };

    public static List<ThreatDetection> Query()
    {
        var names = new Dictionary<ulong, (string name, int severity)>();
        var scope = new ManagementScope($@"\\.\{Namespace}");
        scope.Connect();

        using (var threats = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT ThreatID, ThreatName, SeverityID FROM MSFT_MpThreat")))
        {
            foreach (ManagementBaseObject t in threats.Get())
            {
                using (t)
                {
                    var id = ToUInt64(t["ThreatID"]);
                    names[id] = (t["ThreatName"] as string ?? $"Threat#{id}", (int)ToUInt64(t["SeverityID"]));
                }
            }
        }

        var result = new List<ThreatDetection>();
        using (var detections = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM MSFT_MpThreatDetection")))
        {
            foreach (ManagementBaseObject d in detections.Get())
            {
                using (d)
                {
                    var threatId = ToUInt64(d["ThreatID"]);
                    names.TryGetValue(threatId, out var info);
                    var statusId = (int)ToUInt64(d["ThreatStatusID"]);

                    result.Add(new ThreatDetection(
                        DetectionId: d["DetectionID"] as string ?? Guid.NewGuid().ToString("N"),
                        ThreatName: info.name ?? $"Threat#{threatId}",
                        SeverityId: info.severity,
                        DetectedAt: ToDateTime(d["InitialDetectionTime"]),
                        Resources: JoinResources(d["Resources"]),
                        ActionStatus: StatusText.GetValueOrDefault(statusId, $"狀態碼 {statusId}")));
                }
            }
        }

        return result;
    }

    private static ulong ToUInt64(object? v) =>
        v is null ? 0 : Convert.ToUInt64(v);

    private static DateTimeOffset ToDateTime(object? v)
    {
        if (v is string s && !string.IsNullOrEmpty(s))
        {
            try { return ManagementDateTimeConverter.ToDateTime(s); }
            catch (ArgumentOutOfRangeException) { }
            catch (FormatException) { }
        }
        return DateTimeOffset.MinValue;
    }

    private static string JoinResources(object? v) =>
        v is string[] arr ? string.Join("; ", arr) : (v as string ?? string.Empty);
}
