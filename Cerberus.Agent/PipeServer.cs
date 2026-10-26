using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 與各使用者 Session 的 Tray 通訊：回應 ping（Tray 以此判斷服務是否凍結），
/// 並把告警推送到發生違規的那個 Session。
/// ACL：Authenticated Users 讀寫、SYSTEM 完全控制；不模擬用戶端身分。
/// </summary>
public sealed class PipeServer : BackgroundService
{
    private sealed class Client(StreamWriter writer)
    {
        public StreamWriter Writer { get; } = writer;
        public int? SessionId { get; set; }
        public SemaphoreSlim WriteLock { get; } = new(1, 1);
    }

    private readonly ConcurrentDictionary<Guid, Client> _clients = new();
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<PipeServer> _logger;

    public PipeServer(IOptionsMonitor<CerberusOptions> options, ILogger<PipeServer> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <param name="sessionId">null 表示推送給所有 Session。</param>
    public void Notify(int? sessionId, string title, string text)
    {
        var line = CerberusJson.SerializeLine(new PipeMessage { Kind = PipeMessage.Alert, Title = title, Text = text });
        foreach (var client in _clients.Values)
        {
            if (sessionId is null || client.SessionId is null || client.SessionId == sessionId)
                _ = WriteAsync(client, line, CancellationToken.None);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        bool first = true;
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe(first);
                first = false;
                await pipe.WaitForConnectionAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "建立 Named Pipe 失敗");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                continue;
            }

            _ = HandleClientAsync(pipe, stoppingToken);
        }
    }

    private static NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        // 第一個實例搶先建立，防止使用者程序事先佔用同名管道冒充服務
        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(PipeMessage.PipeName, PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, options, 0, 0, security);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var id = Guid.NewGuid();
        var utf8 = new UTF8Encoding(false);
        await using (pipe)
        using (var reader = new StreamReader(pipe, utf8))
        await using (var writer = new StreamWriter(pipe, utf8) { AutoFlush = true })
        {
            var client = new Client(writer);
            _clients[id] = client;
            try
            {
                while (!ct.IsCancellationRequested && await reader.ReadLineAsync(ct) is { } line)
                {
                    PipeMessage? message;
                    try { message = JsonSerializer.Deserialize<PipeMessage>(line, CerberusJson.Options); }
                    catch (JsonException) { continue; }

                    switch (message?.Kind)
                    {
                        case PipeMessage.Hello:
                            client.SessionId = message.SessionId;
                            await WriteAsync(client, Pong(), ct);
                            break;
                        case PipeMessage.Ping:
                            await WriteAsync(client, Pong(), ct);
                            break;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Tray 結束或斷線
            }
            finally
            {
                _clients.TryRemove(id, out _);
            }
        }
    }

    private string Pong() => CerberusJson.SerializeLine(new PipeMessage
    {
        Kind = PipeMessage.Pong,
        Mode = _options.CurrentValue.Mode,
        ServerUrl = _options.CurrentValue.ServerUrl
    });

    private static async Task WriteAsync(Client client, string line, CancellationToken ct)
    {
        await client.WriteLock.WaitAsync(ct);
        try
        {
            await client.Writer.WriteLineAsync(line.AsMemory(), ct);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
        }
        finally
        {
            client.WriteLock.Release();
        }
    }
}
