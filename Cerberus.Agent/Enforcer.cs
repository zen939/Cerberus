using System.Diagnostics;
using System.Management;
using Cerberus.Shared;

namespace Cerberus.Agent;

/// <summary>
/// 強制處置：先把相關 Windows 服務設為停用（避免 SCM 失敗復原又拉起），
/// 再停止服務、終止整個程序樹。
/// </summary>
public sealed class Enforcer
{
    private static readonly string[] ProtectedDirs =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
    ];

    private readonly ILogger<Enforcer> _logger;

    public Enforcer(ILogger<Enforcer> logger) => _logger = logger;

    /// <summary>System32 / SysWOW64 需系統管理員才能寫入，命中時視為誤判風險，不處置。</summary>
    public static bool IsProtectedPath(string filePath) =>
        ProtectedDirs.Any(dir => !string.IsNullOrEmpty(dir) &&
            filePath.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

    /// <returns>處置過程的描述，供告警使用。</returns>
    public string Enforce(int pid, string filePath, ToolSignature tool)
    {
        if (pid <= 4 || pid == Environment.ProcessId || IsProtectedPath(filePath))
            return "系統保護路徑，略過處置";

        var actions = new List<string>();

        foreach (var service in FindServices(pid, filePath, tool))
        {
            if (DisableAndStop(service))
                actions.Add($"已停用服務 {service["Name"]}");
            service.Dispose();
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
            actions.Add("已終止程序樹");
        }
        catch (ArgumentException)
        {
            actions.Add("程序已結束");
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning(ex, "終止程序 {Pid} 失敗", pid);
            actions.Add($"終止程序失敗：{ex.Message}");
        }

        return string.Join("；", actions);
    }

    private List<ManagementObject> FindServices(int pid, string filePath, ToolSignature tool)
    {
        var matched = new List<ManagementObject>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, PathName, ProcessId, StartMode, State FROM Win32_Service");
            foreach (ManagementObject service in searcher.Get())
            {
                var name = service["Name"] as string ?? string.Empty;
                var pathName = service["PathName"] as string ?? string.Empty;
                var servicePid = service["ProcessId"] is uint p ? (int)p : 0;

                if (servicePid == pid ||
                    pathName.Contains(filePath, StringComparison.OrdinalIgnoreCase) ||
                    tool.Services.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    matched.Add(service);
                }
                else
                {
                    service.Dispose();
                }
            }
        }
        catch (ManagementException ex)
        {
            _logger.LogWarning(ex, "查詢服務清單失敗");
        }
        return matched;
    }

    private bool DisableAndStop(ManagementObject service)
    {
        try
        {
            if (!string.Equals(service["StartMode"] as string, "Disabled", StringComparison.OrdinalIgnoreCase))
                service.InvokeMethod("ChangeStartMode", ["Disabled"]);

            if (!string.Equals(service["State"] as string, "Stopped", StringComparison.OrdinalIgnoreCase))
                service.InvokeMethod("StopService", null);

            return true;
        }
        catch (ManagementException ex)
        {
            _logger.LogWarning(ex, "停用服務 {Name} 失敗", service["Name"]);
            return false;
        }
    }
}
