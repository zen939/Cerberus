namespace Cerberus.Shared;

/// <summary>
/// Server 下發的集中管理設定。欄位為 null 表示「不覆蓋，沿用端點本機設定」。
/// Agent 取回後合併寫入本機 cerberus.json，透過熱重載生效。
/// </summary>
public sealed record ManagedConfig
{
    public EnforcementMode? Mode { get; init; }

    public List<string>? AllowedHosts { get; init; }
}
