using System.Text;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

/// <summary>以 HMAC 簽章送出 JSON 至 Cerberus.Server。</summary>
public sealed class ServerClient
{
    private readonly HttpClient _http;
    private readonly IOptionsMonitor<CerberusOptions> _options;

    public ServerClient(HttpClient http, IOptionsMonitor<CerberusOptions> options)
    {
        _http = http;
        _options = options;
    }

    public bool IsConfigured =>
        Uri.TryCreate(_options.CurrentValue.ServerUrl, UriKind.Absolute, out _) &&
        !string.IsNullOrEmpty(_options.CurrentValue.HostKey);

    /// <returns>Server 回應 2xx 才算成功。</returns>
    public async Task<bool> PostAsync(string path, string json, CancellationToken ct)
    {
        if (!IsConfigured)
            return false;

        using var request = Build(HttpMethod.Post, path, json);
        if (request is null)
            return false;

        try
        {
            using var response = await _http.SendAsync(request, ct);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>HMAC GET（內文為空字串，簽章仍涵蓋時間戳）。失敗回傳 null。</summary>
    public async Task<string?> GetAsync(string path, CancellationToken ct)
    {
        if (!IsConfigured)
            return null;

        using var request = Build(HttpMethod.Get, path, string.Empty);
        if (request is null)
            return null;

        try
        {
            using var response = await _http.SendAsync(request, ct);
            return response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync(ct) : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }

    private HttpRequestMessage? Build(HttpMethod method, string path, string body)
    {
        var options = _options.CurrentValue;
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var request = new HttpRequestMessage(method, new Uri(new Uri(options.ServerUrl), path));
        if (method != HttpMethod.Get)
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");

        request.Headers.Add(HmacSigner.HostHeader, Environment.MachineName);
        request.Headers.Add(HmacSigner.TimestampHeader, timestamp.ToString());
        request.Headers.Add(HmacSigner.SignatureHeader, HmacSigner.Sign(options.HostKey, timestamp, body));
        return request;
    }
}
