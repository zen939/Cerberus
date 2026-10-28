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
        menu.Items.Add("強化稽核（只檢查）", null, (_, _) => OnHardenAudit());
        menu.Items.Add("套用強化…", null, (_, _) => OnHardenApply());
        menu.Items.Add("快速掃描", null, (_, _) => OnQuickScan());
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

    private void OnHardenAudit() => RequestAction("HardenAudit", confirm: false);

    private void OnQuickScan() => RequestAction("DefenderQuickScan", confirm: false);

    private void OnHardenApply()
    {
        // 套用強化會改系統設定，先明確告知影響
        var r = System.Windows.MessageBox.Show(
            "「套用強化」會以系統權限變更本機安全設定，包含：\n\n" +
            "• 停用遠端桌面 (RDP) — 若你以 RDP 連入會被切斷\n" +
            "• 停用 SMBv1、啟用 LSA 保護 — 需重新開機才生效\n" +
            "• 開啟防火牆、停用 AutoRun、停用 Guest 存取\n" +
            "• 開啟 PowerShell 稽核、更新病毒碼並掃描\n\n" +
            "確定要立即套用嗎？",
            "Cerberus — 套用強化", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (r == MessageBoxResult.Yes)
            RequestAction("HardenApply", confirm: false);
    }

    private async void RequestAction(string action, bool confirm)
    {
        if (_client is null)
            return;
        if (!await _client.SendActionAsync(action))
            _icon?.ShowBalloonTip(4000, "Cerberus", "核心服務未連線，無法執行。", ToolTipIcon.Error);
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
