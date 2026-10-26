using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>把告警 / 失聯通知轉發到企業 Webhook（Teams / Slack 相容的 {"text": ...}）。</summary>
public sealed class WebhookForwarder
{
    private readonly HttpClient _http;
    private readonly IOptionsMonitor<ServerOptions> _options;
    private readonly ILogger<WebhookForwarder> _logger;

    public WebhookForwarder(HttpClient http, IOptionsMonitor<ServerOptions> options, ILogger<WebhookForwarder> logger)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    public async Task SendAsync(string text, CancellationToken ct = default)
    {
        var url = _options.CurrentValue.WebhookUrl;
        if (string.IsNullOrWhiteSpace(url))
            return;

        try
        {
            var body = JsonSerializer.Serialize(new { text });
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync(url, content, ct);
            if (!response.IsSuccessStatusCode)
                _logger.LogWarning("Webhook 回應 {Status}", (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogWarning(ex, "Webhook 轉發失敗");
        }
    }
}
