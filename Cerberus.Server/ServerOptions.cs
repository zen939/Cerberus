namespace Cerberus.Server;

public sealed class ServerOptions
{
    public const string SectionName = "Cerberus";

    /// <summary>每台主機各自的 HMAC 金鑰（主機名 → 金鑰）。</summary>
    public Dictionary<string, string> HostKeys { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>找不到專屬金鑰時的共用金鑰（建議仍以 HostKeys 為主）。</summary>
    public string DefaultKey { get; set; } = string.Empty;

    /// <summary>允許的時間戳誤差（秒），防重放。</summary>
    public int ClockSkewSeconds { get; set; } = 300;

    /// <summary>超過此秒數未收到心跳即判定離線。</summary>
    public int OfflineThresholdSeconds { get; set; } = 180;

    public int OfflineCheckIntervalSeconds { get; set; } = 30;

    /// <summary>轉發告警與失聯通知的 Webhook（Teams / Slack / SIEM）。</summary>
    public string WebhookUrl { get; set; } = string.Empty;

    /// <summary>
    /// 管理介面與 /api/admin/* 的簡易權杖。留空＝不設防（僅限開發）。
    /// 正式環境改接公司 OAuth/OIDC：見 AdminAuth.cs 的 TODO。
    /// </summary>
    public string AdminToken { get; set; } = string.Empty;
}
