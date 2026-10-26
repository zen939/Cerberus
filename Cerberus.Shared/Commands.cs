namespace Cerberus.Shared;

/// <summary>
/// Server 可下令給 Agent 的「白名單」動作。Agent 只執行此列舉內的固定動作，
/// 不接受任意命令字串，避免指令通道淪為遠端代碼執行。
/// </summary>
public enum CommandAction
{
    DefenderQuickScan,
    DefenderFullScan,
    DefenderUpdateSignature,
    HardenAudit,
    HardenApply
}

public enum CommandStatus
{
    Pending,    // 已排入，Agent 尚未取走
    Dispatched, // Agent 已取走，執行中
    Completed,  // 已回報結果
    Failed
}

public sealed record CommandMessage
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string HostName { get; init; }
    public required CommandAction Action { get; init; }
    public string? RequestedBy { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public CommandStatus Status { get; set; } = CommandStatus.Pending;
    public DateTimeOffset? DispatchedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public bool? Success { get; set; }
    public string? Output { get; set; }
}

/// <summary>Agent 執行完指令後回報的結果。</summary>
public sealed record CommandResult
{
    public required string CommandId { get; init; }
    public required string HostName { get; init; }
    public required bool Success { get; init; }
    public string? Output { get; init; }
    public DateTimeOffset CompletedAt { get; init; } = DateTimeOffset.UtcNow;
}
