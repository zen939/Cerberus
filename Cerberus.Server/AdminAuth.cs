using Microsoft.Extensions.Options;

namespace Cerberus.Server;

/// <summary>
/// 管理介面授權（可插拔樁）。目前用簡易共用權杖（X-Admin-Token 標頭或 ?token= 查詢字串）。
///
/// TODO 接公司 OAuth/OIDC：
///   1. builder.Services.AddAuthentication(OpenIdConnectDefaults...).AddOpenIdConnect(...)
///   2. 將 IsAuthorized 改為檢查 ctx.User.Identity.IsAuthenticated 與所需角色/群組
///   3. 管理 API 改用 [Authorize] 或 RequireAuthorization()，前端走標準 OIDC 登入導向
/// 現階段刻意保持單純，讓之後替換時不動到業務邏輯。
/// </summary>
public sealed class AdminAuth
{
    private readonly IOptionsMonitor<ServerOptions> _options;

    public AdminAuth(IOptionsMonitor<ServerOptions> options) => _options = options;

    public bool IsAuthorized(HttpContext ctx)
    {
        var expected = _options.CurrentValue.AdminToken;
        if (string.IsNullOrEmpty(expected))
            return true; // 未設權杖＝開發模式不設防

        var given = ctx.Request.Headers["X-Admin-Token"].ToString();
        if (string.IsNullOrEmpty(given))
            given = ctx.Request.Query["token"].ToString();

        return CryptographicEquals(expected, given);
    }

    private static bool CryptographicEquals(string a, string b)
    {
        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
