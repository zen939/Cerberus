using System.Text.Json;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>
/// 輪詢 Server 取待處理指令並執行、回報結果。
/// 採「Agent 主動拉取」而非 Server 推送，不需在端點開任何入站埠。
/// </summary>
public sealed class CommandWorker : BackgroundService
{
    private readonly ServerClient _server;
    private readonly CommandExecutor _executor;
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<CommandWorker> _logger;

    public CommandWorker(ServerClient server, CommandExecutor executor,
        IOptionsMonitor<CerberusOptions> options, ILogger<CommandWorker> logger)
    {
        _server = server;
        _executor = executor;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "輪詢指令失敗");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(5, _options.CurrentValue.CommandPollSeconds)), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task PollOnceAsync(CancellationToken ct)
    {
        var json = await _server.GetAsync("api/commands", ct);
        if (string.IsNullOrEmpty(json))
            return;

        var commands = JsonSerializer.Deserialize<List<CommandMessage>>(json, CerberusJson.Options);
        if (commands is null)
            return;

        foreach (var cmd in commands)
        {
            var (ok, output) = await _executor.ExecuteAsync(cmd.Action, ct);

            var result = new CommandResult
            {
                CommandId = cmd.Id,
                HostName = Environment.MachineName,
                Success = ok,
                Output = output
            };
            await _server.PostAsync("api/command-result", JsonSerializer.Serialize(result, CerberusJson.Options), ct);
        }
    }
}
