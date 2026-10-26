using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Cerberus.Shared;

namespace Cerberus.Tray;

/// <summary>
/// 連線至 Agent 的 Named Pipe，每 2 秒送 ping。
/// 連續逾時視同服務無回應（被凍結或已被終止），直接向 Server 回報。
/// </summary>
public sealed class PipeClient : IDisposable
{
    private static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan PongTimeout = TimeSpan.FromSeconds(10);

    private readonly int _sessionId;
    private readonly CancellationTokenSource _cts = new();
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private DateTime _lastPong = DateTime.UtcNow;
    private bool _reportedUnresponsive;
    private string? _serverUrl;

    /// <summary>收到 Agent 推送告警（title, text）。</summary>
    public event Action<string, string>? AlertReceived;

    /// <summary>連線狀態改變（是否連線、模式文字）。</summary>
    public event Action<bool, string?>? StatusChanged;

    public PipeClient(int sessionId) => _sessionId = sessionId;

    public void Start() => _ = RunAsync(_cts.Token);

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeClientStream(".", PipeMessage.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(3000, ct);

                var utf8 = new UTF8Encoding(false);
                using var reader = new StreamReader(pipe, utf8);
                await using var writer = new StreamWriter(pipe, utf8) { AutoFlush = true };

                _lastPong = DateTime.UtcNow;
                await writer.WriteLineAsync(CerberusJson.SerializeLine(
                    new PipeMessage { Kind = PipeMessage.Hello, SessionId = _sessionId }).AsMemory(), ct);

                var pinger = PingLoopAsync(writer, ct);
                await ReadLoopAsync(reader, ct);
                await pinger;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException)
            {
                if (ct.IsCancellationRequested)
                    return;
            }

            StatusChanged?.Invoke(false, null);
            await ReportIfUnresponsiveAsync(ct);

            try { await Task.Delay(PingInterval, ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task PingLoopAsync(StreamWriter writer, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(PingInterval, ct);
                await writer.WriteLineAsync(CerberusJson.SerializeLine(
                    new PipeMessage { Kind = PipeMessage.Ping }).AsMemory(), ct);

                // 逾時未收到 pong：服務可能被凍結
                if (DateTime.UtcNow - _lastPong > PongTimeout)
                {
                    await ReportIfUnresponsiveAsync(ct);
                    return; // 重建連線
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    private async Task ReadLoopAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && await reader.ReadLineAsync(ct) is { } line)
        {
            PipeMessage? msg;
            try { msg = JsonSerializer.Deserialize<PipeMessage>(line, CerberusJson.Options); }
            catch (JsonException) { continue; }

            switch (msg?.Kind)
            {
                case PipeMessage.Pong:
                    _lastPong = DateTime.UtcNow;
                    _reportedUnresponsive = false;
                    _serverUrl = msg.ServerUrl;
                    StatusChanged?.Invoke(true, msg.Mode?.ToString());
                    break;
                case PipeMessage.Alert:
                    AlertReceived?.Invoke(msg.Title ?? "Cerberus", msg.Text ?? string.Empty);
                    break;
            }
        }
    }

    private async Task ReportIfUnresponsiveAsync(CancellationToken ct)
    {
        if (_reportedUnresponsive || string.IsNullOrEmpty(_serverUrl))
            return;
        _reportedUnresponsive = true;

        var report = new TrayReport
        {
            HostName = Environment.MachineName,
            UserName = Environment.UserName,
            Details = "Tray 偵測到核心守護服務無回應（可能遭凍結或終止）"
        };

        try
        {
            await _http.PostAsJsonAsync(new Uri(new Uri(_serverUrl), "api/tray-report"), report, CerberusJson.Options, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
        _http.Dispose();
    }
}
