using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Forms;
using Application = System.Windows.Application;

namespace Cerberus.Tray;

public partial class App : Application
{
    private NotifyIcon? _icon;
    private PipeClient? _client;
    private bool _connected;
    private string? _mode;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _icon = new NotifyIcon
        {
            Icon = LoadAppIcon(),
            Visible = true,
            Text = "Cerberus 端點守護"
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("狀態：連線中…").Enabled = false;
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("結束", null, (_, _) => Shutdown());
        _icon.ContextMenuStrip = menu;

        _client = new PipeClient(Process.GetCurrentProcess().SessionId);
        _client.AlertReceived += OnAlert;
        _client.StatusChanged += OnStatusChanged;
        _client.Start();
    }

    // 從嵌入資源載入 Cerberus 圖示；失敗則退回系統盾牌
    private static Icon LoadAppIcon()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("Cerberus.Tray.Assets.cerberus.ico");
            if (stream is not null)
                return new Icon(stream, new System.Drawing.Size(32, 32));
        }
        catch (Exception ex) when (ex is IOException or ArgumentException)
        {
        }
        return SystemIcons.Shield;
    }

    private void OnAlert(string title, string text) => Dispatcher.Invoke(() =>
        _icon?.ShowBalloonTip(5000, title, text, ToolTipIcon.Warning));

    private void OnStatusChanged(bool connected, string? mode) => Dispatcher.Invoke(() =>
    {
        _connected = connected;
        if (mode is not null)
            _mode = mode;
        if (_icon?.ContextMenuStrip?.Items.Count > 0)
            _icon.ContextMenuStrip.Items[0].Text = connected
                ? $"狀態：守護中（{_mode ?? "?"}）"
                : "狀態：服務無回應";
        if (_icon is not null)
            _icon.Text = connected ? $"Cerberus 端點守護（{_mode ?? "?"}）" : "Cerberus：服務無回應";
    });

    protected override void OnExit(ExitEventArgs e)
    {
        _client?.Dispose();
        if (_icon is not null)
        {
            _icon.Visible = false;
            _icon.Dispose();
        }
        base.OnExit(e);
    }
}
