using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Server;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// 讓 /api/hosts 等回應也用字串列舉（與 CerberusJson 一致）
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.Configure<ServerOptions>(builder.Configuration.GetSection(ServerOptions.SectionName));
builder.Services.AddSingleton<HostRegistry>();
builder.Services.AddSingleton<AlertStore>();
builder.Services.AddSingleton<CommandQueue>();
builder.Services.AddSingleton<AdminAuth>();
builder.Services.AddHttpClient<WebhookForwarder>(c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddHostedService<OfflineMonitor>();

var app = builder.Build();

// 啟動時檢查金鑰策略：共用 DefaultKey 不安全，提醒改用每台獨立 HostKeys
{
    var opts = app.Services.GetRequiredService<IOptions<ServerOptions>>().Value;
    var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
    if (!string.IsNullOrEmpty(opts.DefaultKey))
        startupLog.LogWarning("偵測到共用 DefaultKey：一台外洩即全體淪陷。正式環境請改用每台獨立 HostKeys 並清空 DefaultKey（見 tools\\New-HostKey.ps1）。");
    else if (opts.HostKeys.Count == 0)
        startupLog.LogWarning("尚未設定任何 HostKeys，且 DefaultKey 為空：所有 Agent 請求都會被拒絕。");
    else
        startupLog.LogInformation("金鑰策略：每台獨立 HostKeys（{Count} 台已註冊）。", opts.HostKeys.Count);
}

// 管理介面靜態頁（wwwroot/index.html）
app.UseDefaultFiles();
app.UseStaticFiles();

// 讀取原始內文並驗證 HMAC 簽章；通過回傳 body，否則已寫入回應
static async Task<string?> VerifyAsync(HttpContext ctx, IOptionsMonitor<ServerOptions> opts)
{
    var options = opts.CurrentValue;
    var host = ctx.Request.Headers[HmacSigner.HostHeader].ToString();
    var tsRaw = ctx.Request.Headers[HmacSigner.TimestampHeader].ToString();
    var signature = ctx.Request.Headers[HmacSigner.SignatureHeader].ToString();

    using var reader = new StreamReader(ctx.Request.Body);
    var body = await reader.ReadToEndAsync();

    if (string.IsNullOrEmpty(host) ||
        !long.TryParse(tsRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ts) ||
        string.IsNullOrEmpty(signature))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return null;
    }

    // 時間戳誤差檢查（防重放）
    if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts) > options.ClockSkewSeconds)
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return null;
    }

    bool perHost = options.HostKeys.TryGetValue(host, out var key) && !string.IsNullOrEmpty(key);
    if (!perHost)
        key = options.DefaultKey;

    if (string.IsNullOrEmpty(key) || !HmacSigner.Verify(key, ts, body, signature))
    {
        // 未註冊於 HostKeys 且無（或不符）共用金鑰 → 拒絕，記錄以利稽核
        ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Auth")
            .LogWarning("拒絕主機 {Host} 的請求（簽章驗證失敗或未註冊金鑰）", host);
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return null;
    }

    return body;
}

static T? TryDeserialize<T>(string body)
{
    try { return JsonSerializer.Deserialize<T>(body, CerberusJson.Options); }
    catch (JsonException) { return default; }
}

app.MapPost("/api/heartbeat", async (HttpContext ctx, IOptionsMonitor<ServerOptions> opts,
    HostRegistry registry, WebhookForwarder webhook) =>
{
    var body = await VerifyAsync(ctx, opts);
    if (body is null)
        return Results.Empty;

    if (TryDeserialize<HeartbeatMessage>(body) is not { } hb)
        return Results.BadRequest();

    if (registry.Update(hb))
        await webhook.SendAsync($"✅ 主機 {hb.HostName} 監控已恢復連線（使用者 {hb.UserName ?? "未知"}）");

    return Results.Ok();
});

app.MapPost("/api/alert", async (HttpContext ctx, IOptionsMonitor<ServerOptions> opts,
    WebhookForwarder webhook, ILoggerFactory lf) =>
{
    var body = await VerifyAsync(ctx, opts);
    if (body is null)
        return Results.Empty;

    if (TryDeserialize<AlertMessage>(body) is not { } alert)
        return Results.BadRequest();

    ctx.RequestServices.GetRequiredService<AlertStore>().Add(alert);

    lf.CreateLogger("Alert").LogWarning("[{Type}] {Host}/{User}: {Details}",
        alert.Type, alert.HostName, alert.UserName, alert.Details);

    var icon = alert.Enforced ? "🛑" : "⚠️";
    await webhook.SendAsync(
        $"{icon} [{alert.Type}] 主機 {alert.HostName}（{alert.UserName ?? "未知"}）：{alert.Details}");

    return Results.Ok();
});

// 未簽章的 Tray 回報，標註為未驗證來源
app.MapPost("/api/tray-report", async (TrayReport report, WebhookForwarder webhook) =>
{
    await webhook.SendAsync($"⚠️ [TrayReport/未驗證] 主機 {report.HostName}（{report.UserName ?? "未知"}）：{report.Details}");
    return Results.Ok();
});

// ── Agent 指令通道（HMAC 驗章；Agent 輪詢取指令、回報結果）──

app.MapGet("/api/commands", async (HttpContext ctx, IOptionsMonitor<ServerOptions> opts, CommandQueue commands) =>
{
    var body = await VerifyAsync(ctx, opts);   // GET 內文為空字串，簽章仍涵蓋時間戳
    if (body is null)
        return Results.Empty;

    var host = ctx.Request.Headers[HmacSigner.HostHeader].ToString();
    return Results.Ok(commands.TakePending(host));
});

app.MapPost("/api/command-result", async (HttpContext ctx, IOptionsMonitor<ServerOptions> opts,
    CommandQueue commands, ILoggerFactory lf) =>
{
    var body = await VerifyAsync(ctx, opts);
    if (body is null)
        return Results.Empty;

    if (TryDeserialize<CommandResult>(body) is not { } result)
        return Results.BadRequest();

    commands.Complete(result);
    lf.CreateLogger("Command").LogInformation("指令 {Id} 於 {Host} 完成：success={Ok}",
        result.CommandId, result.HostName, result.Success);
    return Results.Ok();
});

// ── 管理介面 API（權杖授權；之後接 OAuth）──

RouteGroupBuilder admin = app.MapGroup("/api/admin");
admin.AddEndpointFilter(async (ctx, next) =>
    ctx.HttpContext.RequestServices.GetRequiredService<AdminAuth>().IsAuthorized(ctx.HttpContext)
        ? await next(ctx)
        : Results.Unauthorized());

admin.MapGet("/hosts", (HostRegistry registry) => Results.Ok(registry.Snapshot()));
admin.MapGet("/alerts", (AlertStore store, int? take) => Results.Ok(store.Recent(take ?? 100)));
admin.MapGet("/commands", (CommandQueue commands, int? take) => Results.Ok(commands.Recent(take ?? 100)));

admin.MapPost("/commands", (CommandEnqueueRequest req, CommandQueue commands, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.HostName))
        return Results.BadRequest("hostName required");

    var by = ctx.Request.Headers["X-Admin-User"].ToString();
    var cmd = commands.Enqueue(req.HostName, req.Action, string.IsNullOrEmpty(by) ? "admin" : by);
    return Results.Ok(cmd);
});

app.MapGet("/api/hosts", (HostRegistry registry) => Results.Ok(registry.Snapshot()));
app.MapGet("/health", () => Results.Ok("ok"));

app.Run();

internal sealed record CommandEnqueueRequest(string HostName, CommandAction Action);
