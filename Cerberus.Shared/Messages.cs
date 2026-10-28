using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Shared;

public static class AlertTypes
{
    public const string Detection = "Detection";
    public const string PortOnly = "PortOnly";
    public const string RdpEnabled = "RdpEnabled";
    public const string MalwareDetected = "MalwareDetected";
    public const string LogonFailureBurst = "LogonFailureBurst";
    public const string RemoteLogon = "RemoteLogon";
    public const string AccountLockout = "AccountLockout";
    public const string UsbInserted = "UsbInserted";
    public const string UsbBlocked = "UsbBlocked";
    public const string AgentStarted = "AgentStarted";
    public const string AgentStopped = "AgentStopped";
    public const string AgentUnresponsive = "AgentUnresponsive";
    public const string HostOffline = "HostOffline";
    public const string HostRecovered = "HostRecovered";
}

public sealed record AlertMessage
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string HostName { get; init; }
    public string? UserName { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public required string Type { get; init; }
    public required string Details { get; init; }
    public string? ToolName { get; init; }
    public string? ProcessName { get; init; }
    public int? ProcessId { get; init; }
    public string? FilePath { get; init; }
    public EnforcementMode? Mode { get; init; }

    /// <summary>是否已執行處置（終止程序 / 停用服務 / 修正設定）。</summary>
    public bool Enforced { get; init; }
}

public sealed record HeartbeatMessage
{
    public required string HostName { get; init; }
    public string? UserName { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public required string AgentVersion { get; init; }
    public EnforcementMode Mode { get; init; }
}

/// <summary>Tray 在服務失聯時送出的回報（未簽章，Server 端標註為未驗證來源）。</summary>
public sealed record TrayReport
{
    public required string HostName { get; init; }
    public string? UserName { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public required string Details { get; init; }
}

/// <summary>Agent 與 Tray 之間的 Named Pipe 訊息，一行一個 JSON。</summary>
public sealed record PipeMessage
{
    public const string PipeName = "CerberusAgent";

    public const string Hello = "hello";
    public const string Ping = "ping";
    public const string Pong = "pong";
    public const string Alert = "alert";
    public const string Action = "action"; // Tray → 服務：請求執行白名單動作

    public required string Kind { get; init; }
    public int? SessionId { get; init; }
    public EnforcementMode? Mode { get; init; }
    public string? ServerUrl { get; init; }
    public string? Title { get; init; }
    public string? Text { get; init; }

    /// <summary>Kind=action 時，要執行的 CommandAction 名稱。</summary>
    public string? ActionName { get; init; }
}

public static class CerberusJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>單行輸出，供 Named Pipe 逐行傳送。</summary>
    public static string SerializeLine<T>(T value) => JsonSerializer.Serialize(value, Options);
}
