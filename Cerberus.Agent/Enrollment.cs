using System.Net.Http.Json;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Shared;

namespace Cerberus.Agent;

/// <summary>
/// 首次啟動註冊：若 HostKey 為空且已設 EnrollmentToken，向 Server 換取專屬 HostKey
/// 並寫回 cerberus.json。在設定載入前執行，之後即以該金鑰通訊。
/// </summary>
public static class Enrollment
{
    public static async Task EnsureEnrolledAsync(AgentPaths paths)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(await File.ReadAllTextAsync(paths.ConfigFile));
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return;
        }

        var c = root?["Cerberus"];
        if (c is null)
            return;

        var hostKey = c["HostKey"]?.GetValue<string>() ?? string.Empty;
        var token = c["EnrollmentToken"]?.GetValue<string>() ?? string.Empty;
        var serverUrl = c["ServerUrl"]?.GetValue<string>() ?? string.Empty;
        var thumbprint = c["ServerCertThumbprint"]?.GetValue<string>() ?? string.Empty;

        if (!string.IsNullOrEmpty(hostKey) || string.IsNullOrEmpty(token) ||
            !Uri.TryCreate(serverUrl, UriKind.Absolute, out var baseUri))
            return; // 已有金鑰或未設定註冊

        try
        {
            using var handler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                    {
                        var pin = thumbprint.Replace(" ", "").Replace(":", "");
                        if (string.IsNullOrEmpty(pin))
                            return errors == SslPolicyErrors.None;
                        return cert is not null &&
                            string.Equals(cert.GetCertHashString(), pin, StringComparison.OrdinalIgnoreCase);
                    }
                }
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            var request = new EnrollRequest
            {
                HostName = Environment.MachineName,
                Token = token,
                OsVersion = RuntimeInformation.OSDescription,
                AgentVersion = typeof(Enrollment).Assembly.GetName().Version?.ToString()
            };

            using var resp = await http.PostAsJsonAsync(new Uri(baseUri, "api/enroll"), request, CerberusJson.Options);
            if (!resp.IsSuccessStatusCode)
                return;

            var result = await resp.Content.ReadFromJsonAsync<EnrollResponse>(CerberusJson.Options);
            if (result is null || string.IsNullOrEmpty(result.HostKey))
                return;

            // 寫回設定（存檔後服務即以此金鑰通訊）
            c["HostKey"] = result.HostKey;
            await File.WriteAllTextAsync(paths.ConfigFile,
                root!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            // 註冊失敗不阻斷啟動；下次啟動再試（基本防護不受影響）
        }
    }
}
