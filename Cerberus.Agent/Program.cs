using System.Net.Security;
using Cerberus.Agent;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

var paths = new AgentPaths();
paths.EnsureConfig();

// 首次啟動若設有 EnrollmentToken 且無 HostKey，先向 Server 註冊換取專屬金鑰（寫回設定）
await Enrollment.EnsureEnrolledAsync(paths);

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "CerberusAgent");

// 設定來自 %ProgramData%\Cerberus\cerberus.json，存檔即熱重載
builder.Configuration.AddJsonFile(paths.ConfigFile, optional: false, reloadOnChange: true);
builder.Services.Configure<CerberusOptions>(builder.Configuration.GetSection(CerberusOptions.SectionName));

builder.Services.AddSingleton(paths);
builder.Services.AddSingleton<ProcessInspector>();
builder.Services.AddSingleton<Enforcer>();
builder.Services.AddSingleton<CommandExecutor>();
builder.Services.AddSingleton<ProcessStartWatcher>();
builder.Services.AddSingleton<UsbConfigProvider>();
builder.Services.AddSingleton<PipeServer>();
builder.Services.AddSingleton<AlertQueue>();
builder.Services.AddHttpClient<ServerClient>(c => c.Timeout = TimeSpan.FromSeconds(10))
    .ConfigurePrimaryHttpMessageHandler(sp =>
    {
        var options = sp.GetRequiredService<IOptionsMonitor<CerberusOptions>>();
        return new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                // 設定指紋時只信任該憑證（含自簽）；未設定時走預設鏈驗證
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    var pin = options.CurrentValue.ServerCertThumbprint
                        ?.Replace(" ", string.Empty).Replace(":", string.Empty);
                    if (string.IsNullOrEmpty(pin))
                        return errors == SslPolicyErrors.None;
                    return cert is not null &&
                        string.Equals(cert.GetCertHashString(), pin, StringComparison.OrdinalIgnoreCase);
                }
            }
        };
    });

// AlertQueue / PipeServer 既是服務又被注入，取同一實例
builder.Services.AddHostedService(sp => sp.GetRequiredService<AlertQueue>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<PipeServer>());
builder.Services.AddHostedService<LifecycleReporter>();
builder.Services.AddHostedService<DetectionWorker>();
builder.Services.AddHostedService<RdpGuard>();
builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<CommandWorker>();
builder.Services.AddHostedService<DefenderThreatWatcher>();
builder.Services.AddHostedService<LoginWatcher>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<UsbConfigProvider>());
builder.Services.AddHostedService<UsbWatcher>();
builder.Services.AddHostedService<ConfigSyncWorker>();

var host = builder.Build();
host.Run();
