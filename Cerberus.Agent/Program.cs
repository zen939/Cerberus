using Cerberus.Agent;
using Cerberus.Shared;

var paths = new AgentPaths();
paths.EnsureConfig();

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
builder.Services.AddSingleton<PipeServer>();
builder.Services.AddSingleton<AlertQueue>();
builder.Services.AddHttpClient<ServerClient>(c => c.Timeout = TimeSpan.FromSeconds(10));

// AlertQueue / PipeServer 既是服務又被注入，取同一實例
builder.Services.AddHostedService(sp => sp.GetRequiredService<AlertQueue>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<PipeServer>());
builder.Services.AddHostedService<LifecycleReporter>();
builder.Services.AddHostedService<DetectionWorker>();
builder.Services.AddHostedService<RdpGuard>();
builder.Services.AddHostedService<HeartbeatWorker>();
builder.Services.AddHostedService<CommandWorker>();
builder.Services.AddHostedService<DefenderThreatWatcher>();

var host = builder.Build();
host.Run();
