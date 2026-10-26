using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Shared;

/// <summary>
/// 簽章 = Base64(HMAC-SHA256(key, "{unix 秒數}\n{body}"))。
/// 時間戳一併簽入，Server 端再檢查時間差防重放。
/// </summary>
public static class HmacSigner
{
    public const string HostHeader = "X-Cerberus-Host";
    public const string TimestampHeader = "X-Cerberus-Timestamp";
    public const string SignatureHeader = "X-Cerberus-Signature";

    public static string Sign(string key, long unixSeconds, string body)
    {
        var payload = Encoding.UTF8.GetBytes(unixSeconds.ToString(CultureInfo.InvariantCulture) + "\n" + body);
        var hash = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), payload);
        return Convert.ToBase64String(hash);
    }

    public static bool Verify(string key, long unixSeconds, string body, string signature)
    {
        byte[] given;
        try { given = Convert.FromBase64String(signature); }
        catch (FormatException) { return false; }

        var expected = Convert.FromBase64String(Sign(key, unixSeconds, body));
        return CryptographicOperations.FixedTimeEquals(expected, given);
    }
}
