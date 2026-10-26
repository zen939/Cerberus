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

    /// <summary>
    /// Server TLS 憑證指紋（SHA-1，十六進位）。設定後 Agent 只信任此指紋的憑證，
    /// 即使自簽也安全、且可抵擋中間人；留空則走作業系統預設憑證驗證。
    /// </summary>
    public string ServerCertThumbprint { get; set; } = string.Empty;

    public int ScanIntervalSeconds { get; set; } = 3;

    public int HeartbeatIntervalSeconds { get; set; } = 60;

    public int RdpCheckIntervalSeconds { get; set; } = 60;

    /// <summary>輪詢 Server 指令的間隔秒數。</summary>
    public int CommandPollSeconds { get; set; } = 20;

    /// <summary>監看 Windows Defender 威脅紀錄並回報（含即時防護自動攔截）。</summary>
    public bool ReportDefenderThreats { get; set; } = true;

    public int DefenderThreatPollSeconds { get; set; } = 60;

    /// <summary>監看 Windows 安全性事件，偵測異常登入（暴力破解、遠端桌面登入、帳號鎖定）。</summary>
    public bool WatchLogons { get; set; } = true;

    /// <summary>同一帳號在時間窗內登入失敗達此次數即視為暴力破解。</summary>
    public int FailedLogonThreshold { get; set; } = 5;

    public int FailedLogonWindowMinutes { get; set; } = 5;

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
