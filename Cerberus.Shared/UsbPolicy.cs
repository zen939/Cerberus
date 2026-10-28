namespace Cerberus.Shared;

/// <summary>可移除儲存裝置（USB 隨身碟/行動硬碟）接入政策。</summary>
public enum UsbPolicy
{
    /// <summary>只告警，不限制。</summary>
    Audit,
    /// <summary>允許接入但強制唯讀（防資料外洩/寫入惡意程式）。</summary>
    ReadOnly,
    /// <summary>非白名單裝置一律卸載、禁止存取。</summary>
    Block
}

/// <summary>由 Server 下發、Agent 套用的 USB 管控設定。</summary>
public sealed record UsbConfig
{
    public UsbPolicy Policy { get; init; } = UsbPolicy.Audit;

    /// <summary>白名單：裝置序號（不分大小寫）。Block 模式下僅這些可存取。</summary>
    public List<string> Allowlist { get; init; } = [];

    /// <summary>接入時自動以 Defender 掃描該磁碟。</summary>
    public bool ScanOnInsert { get; init; } = true;
}
