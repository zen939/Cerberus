using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>
/// 管理介面授權。有效權杖 = 後台設定的 AdminToken（DB）優先，否則 ServerOptions.AdminToken（env）。
/// 未設定任何權杖時，/api/admin/* 一律拒絕（安全預設）；首次設定走 bootstrap 端點。
///
/// TODO 接公司 OAuth/OIDC：改以 ctx.User 驗證身分/角色，詳見原設計註解。
/// </summary>
public sealed class AdminAuth
{
    private readonly IOptionsMonitor<ServerOptions> _options;
    private readonly AdminTokenStore _store;

    public AdminAuth(IOptionsMonitor<ServerOptions> options, AdminTokenStore store)
    {
        _options = options;
        _store = store;
    }

    public string EffectiveToken
    {
        get
        {
            var stored = _store.Get();
            return !string.IsNullOrEmpty(stored) ? stored : _options.CurrentValue.AdminToken;
        }
    }

    public bool IsConfigured => !string.IsNullOrEmpty(EffectiveToken);

    public bool IsAuthorized(HttpContext ctx)
    {
        var expected = EffectiveToken;
        if (string.IsNullOrEmpty(expected))
            return false; // 未設權杖 → 拒絕（安全預設）

        var given = ctx.Request.Headers["X-Admin-Token"].ToString();
        if (string.IsNullOrEmpty(given))
            given = ctx.Request.Query["token"].ToString();

        return FixedEquals(expected, given);
    }

    private static bool FixedEquals(string a, string b)
    {
        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
