namespace Cerberus.Shared;

/// <summary>Audit 只告警；Enforce 告警並終止程序、停用對應服務。</summary>
public enum EnforcementMode
{
    Audit,
    Enforce
}

/// <summary>Agent 端設定，對應 %ProgramData%\Cerberus\cerberus.json 的 "Cerberus" 區段。</summary>
public sealed class CerberusOptions
{
    public const string SectionName = "Cerberus";

    public EnforcementMode Mode { get; set; } = EnforcementMode.Audit;

    /// <summary>Cerberus.Server 根網址，例如 https://cerberus.corp.local</summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>本機 HMAC 金鑰，需與 Server 端 HostKeys / DefaultKey 一致。</summary>
    public string HostKey { get; set; } = string.Empty;

    public int ScanIntervalSeconds { get; set; } = 3;

    public int HeartbeatIntervalSeconds { get; set; } = 60;

    public int RdpCheckIntervalSeconds { get; set; } = 60;

    /// <summary>輪詢 Server 指令的間隔秒數。</summary>
    public int CommandPollSeconds { get; set; } = 20;

    /// <summary>監看 Windows Defender 威脅紀錄並回報（含即時防護自動攔截）。</summary>
    public bool ReportDefenderThreats { get; set; } = true;

    public int DefenderThreatPollSeconds { get; set; } = 60;

    /// <summary>巡檢本機遠端桌面（fDenyTSConnections）。</summary>
    public bool GuardRdp { get; set; } = true;

    /// <summary>列入的主機名稱一律只告警、不處置（IT 合規維護用）。</summary>
    public List<string> AllowedHosts { get; set; } = [];

    public List<ToolSignature> Tools { get; set; } = [];
}

/// <summary>一種遠端控制 / 穿透工具的特徵。</summary>
public sealed class ToolSignature
{
    public string Name { get; set; } = string.Empty;

    /// <summary>Authenticode 憑證 Subject 片段（不分大小寫）。</summary>
    public List<string> Signers { get; set; } = [];

    /// <summary>比對程序名稱、OriginalFilename、ProductName、FileDescription、InternalName 的片段。</summary>
    public List<string> Names { get; set; } = [];

    /// <summary>執行檔 SHA-256（十六進位），防剝除簽章並竄改資源的變種。</summary>
    public List<string> Sha256 { get; set; } = [];

    /// <summary>專用通訊埠，僅作輔助證據。</summary>
    public List<int> Ports { get; set; } = [];

    /// <summary>強制模式下要停用的 Windows 服務名稱。</summary>
    public List<string> Services { get; set; } = [];
}
