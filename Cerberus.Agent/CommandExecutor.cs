using System.Diagnostics;
using System.Text;
using Cerberus.Shared;

namespace Cerberus.Agent;

/// <summary>
/// 執行 Server 下令的「白名單」動作。只對應固定 CommandAction，
/// 絕不執行任意命令字串。Defender 透過 MpCmdRun.exe，強化透過隨附腳本。
/// </summary>
public sealed class CommandExecutor
{
    private readonly ILogger<CommandExecutor> _logger;

    public CommandExecutor(ILogger<CommandExecutor> logger) => _logger = logger;

    public async Task<(bool ok, string output)> ExecuteAsync(CommandAction action, CancellationToken ct)
    {
        _logger.LogInformation("執行遠端指令：{Action}", action);
        try
        {
            return action switch
            {
                CommandAction.DefenderQuickScan => await Defender("-Scan -ScanType 1", ct),
                CommandAction.DefenderFullScan => await Defender("-Scan -ScanType 2", ct),
                CommandAction.DefenderUpdateSignature => await Defender("-SignatureUpdate", ct),
                CommandAction.HardenAudit => await Harden(apply: false, ct),
                CommandAction.HardenApply => await Harden(apply: true, ct),
                _ => (false, $"未知動作：{action}")
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "指令執行失敗：{Action}", action);
            return (false, ex.Message);
        }
    }

    private async Task<(bool, string)> Defender(string args, CancellationToken ct)
    {
        var exe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(exe))
            return (false, "找不到 MpCmdRun.exe（Windows Defender 未安裝或路徑不同）");

        var (code, output) = await Run(exe, args, TimeSpan.FromMinutes(30), ct);

        // MpCmdRun 退出碼：0=完成無威脅；2=完成並發現威脅，或已有掃描進行中；
        // 其餘才視為真正的執行失敗。
        var note = code switch
        {
            0 => "掃描完成，未發現威脅",
            2 => "掃描完成並發現威脅，或已有掃描進行中（若有威脅將另發 MalwareDetected 告警）",
            _ => "執行異常"
        };
        return (code is 0 or 2, $"ExitCode={code}（{note}）\n{output}");
    }

    private async Task<(bool, string)> Harden(bool apply, CancellationToken ct)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "Harden-Windows.ps1");
        if (!File.Exists(script))
            return (false, "找不到隨附的 Harden-Windows.ps1");

        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"" + (apply ? " -Apply" : string.Empty);
        var (code, output) = await Run("powershell.exe", args, TimeSpan.FromMinutes(20), ct);
        return (code == 0, $"ExitCode={code}\n{output}");
    }

    private async Task<(int code, string output)> Run(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        var output = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) output.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) output.AppendLine(e.Data); };

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return (-1, $"逾時（>{timeout.TotalMinutes:0} 分）後中止");
        }

        // 輸出可能很長，截斷以免告警過大
        var text = output.ToString().Trim();
        if (text.Length > 4000)
            text = text[^4000..];

        return (proc.ExitCode, text);
    }
}
