# 企業端未授權遠端存取防禦與端點監控系統規劃書（Cerberus）
**文件版本**：v1.1  
**目標系統**：Windows 端點設備、邊界防火牆（NGFW）  
**主要目標**：全面阻斷並即時監控 AnyDesk、TeamViewer、RustDesk、向日葵、內網穿透工具等未授權遠端控制軟體。

### 版本異動（v1.0 → v1.1）
| 項目 | v1.0 | v1.1 修正 |
| :--- | :--- | :--- |
| 防暫停 | 同程序看門狗線程偵測主線程暫停 | 同程序線程會一起被暫停，改由 **外部（Tray / 伺服器心跳）** 偵測 |
| 遺言通報 | `AppDomain.ProcessExit` + `SystemEvents.SessionEnding` | 強制結束時兩者皆不觸發；服務改用 `OnShutdown` / Preshutdown，強殺情境交由伺服器端失聯告警 |
| Chrome Remote Desktop | 檢查 Chrome 參數 `--type=utility` | 被控端實為獨立程序 `remoting_host.exe`，改比對程序名稱 / 簽章 |
| 使用者名稱 | `Environment.UserName`（服務內永遠是 SYSTEM） | `WTSQuerySessionInformation` 取前台登入者 |
| 網路表 | 僅 IPv4 TCP | TCP + UDP、IPv4 + IPv6 |
| 偵測時機 | 僅輪詢網路表 | 增加 WMI 程序啟動事件即時檢查 |
| 判定 | 單一連接埠命中即 Kill | 連接埠僅作輔助證據，需簽章 / 特徵命中才處置 |
| 處置 | `Process.Kill()` | 殺整個程序樹 + 停用並封鎖該工具的 Windows 服務，避免 SCM 拉回 |
| 告警 | 送失敗即丟棄、無驗證 | 本機持久佇列 + 重送、Event Log 備援、HMAC-SHA256 簽章 |
| 部署 | 直接強制模式 | 先 **稽核模式（Audit）** 觀察誤判，再切 **強制模式（Enforce）** |
| 特徵 | 寫死在程式內 | `cerberus.json` 設定檔，可由伺服器派送更新 |

---

## 1. 執行摘要 (Executive Summary)
傳統網路防火牆面對 AnyDesk 與 TeamViewer 等工具時，容易因其自動降級至標準 HTTPS (TCP 443) 或透過雲端中繼站穿透而防禦失效。本專案採行**縱深防禦（Defense in Depth）架構**：
1. **網路邊界層**：以次世代防火牆（NGFW）進行 L7 應用程式識別、DNS 黑名單與專用埠阻斷。
2. **端點主機層**：部署 SYSTEM 權限常駐服務，結合「程序啟動事件」與「網路連線表（TCP/UDP、IPv4/IPv6）」雙路偵測，以數位簽章與二進位中繼資訊比對，做到改名亦可辨識、稽核或即時阻斷並遠端告警。
3. **自我防護與失聯偵測**：SCM 崩潰自動重啟、Tray 與服務雙向心跳、伺服器端失聯告警（Dead Man's Snitch）。

---

## 2. 網路邊界防禦規劃 (Network Perimeter Defense)

### 2.1 應用程式特徵識別 (L7 Application Control)
* **策略設定**：於防火牆 `LAN -> WAN` 出向政策中啟用深度封包檢測（DPI），將以下應用標籤設為 **Block / Deny**：
  * `AnyDesk`、`TeamViewer` / `TeamViewer-Base`
  * `ToDesk`、`RustDesk`、`Sunlogin（向日葵）`、`Splashtop`、`Parsec`、`ScreenConnect`、`Chrome Remote Desktop`
* **SSL 檢測要求**：針對外出 HTTPS (TCP 443) 流量建議開啟 SSL Deep Inspection（需預先透過 GPO 派送企業根憑證），以防止中繼流量以 TLS 加密偽裝。

### 2.2 DNS 與 URL 分類過濾 (Domain Blacklisting)
於防火牆 DNS Filter 與網頁過濾器中加入下列阻擋規則：

| 目標軟體 | 應阻擋網域名稱 (Wildcard / FQDN) |
| :--- | :--- |
| **TeamViewer** | `*.teamviewer.com`、`*.teamviewer.cn` |
| **AnyDesk** | `*.anydesk.com` |
| **RustDesk** | `*.rustdesk.com`（**自架伺服器不經此網域，須搭配 2.3 埠封鎖**） |
| **ToDesk** | `*.todesk.com`、`*.todesk.cn` |
| **向日葵 Sunlogin** | `*.oray.com`、`*.oray.net`、`*.sunlogin.com` |
| **Splashtop** | `*.splashtop.com` |
| **Parsec** | `*.parsec.app`、`*.parsecgaming.com` |
| **Chrome Remote Desktop** | `remotedesktop.google.com`、`remotedesktop-pa.googleapis.com` |
| **內網穿透** | `*.ngrok.io`、`*.ngrok-free.app`、`*.trycloudflare.com`、`*.tailscale.com`、`controlplane.tailscale.com` |

* **DoH 繞過防範**：瀏覽器內建 DNS over HTTPS 會繞過 DNS Filter。須以 GPO 停用瀏覽器 DoH（Chrome `DnsOverHttpsMode=off`、Edge 同名原則、Firefox `DNSOverHTTPS.Enabled=false`），並於防火牆封鎖已知 DoH 端點（`dns.google`、`cloudflare-dns.com`、`dns.quad9.net` 等）。

### 2.3 連線埠出向封鎖 (Outbound Port Filtering)
* **TCP / UDP 5938**：TeamViewer 核心連線埠。
* **TCP 6568 / TCP & UDP 7070**：AnyDesk 核心傳輸與監聽埠。
* **TCP 21115–21119 / UDP 21116**：RustDesk（含自架 hbbs/hbbr 伺服器）。
* **UDP 443 (QUIC)**：防止工具走 QUIC 繞過 TCP 代理檢驗（瀏覽器會自動回退 TCP，影響有限）。

---

## 3. 端點監控系統架構 (Endpoint Agent Architecture)

### 3.1 架構總覽
系統由三個元件組成：

```
                [ 企業 SIEM / 通訊軟體 Webhook (Teams, Slack, LINE) ]
                                     ▲
                                     │ 轉發告警 / 失聯告警
                     ┌───────────────┴───────────────┐
                     │   Cerberus.Server (ASP.NET)   │
                     │   - 接收 Heartbeat / Alert    │
                     │   - HMAC 驗章                 │
                     │   - 3 分鐘失聯主動告警        │
                     └───────────────▲───────────────┘
                                     │ HTTPS POST（HMAC 簽章，每 60 秒心跳）
  ┌──────────────────────────────────┴──┐                 ┌─────────────────────────────┐
  │ Cerberus.Agent (Windows Service)    │── Named Pipe ──►│ Cerberus.Tray (WPF 系統匣)  │
  │ - 權限: NT AUTHORITY\SYSTEM          │◄── 心跳 2 秒 ──│ - 權限: 使用者 Session       │
  │ - 程序啟動事件 + 網路表輪詢          │                 │ - 氣泡通知、狀態顯示         │
  │ - 簽章 / 特徵比對（含快取）          │                 │ - 偵測服務凍結 / 失聯並回報  │
  │ - 稽核 / 強制處置                    │                 └─────────────────────────────┘
  │ - 本機告警佇列（離線補送）           │
  │ - SCM 崩潰自動重啟                   │
  └─────────────────────────────────────┘
```

* **Session 0 隔離**：服務無法直接顯示 UI。Tray 由 `HKLM\...\Run` 於每位使用者登入時啟動。
* **Named Pipe ACL**：`Authenticated Users` 可讀寫、`SYSTEM` 完全控制；伺服端不對用戶端做身分模擬。

### 3.2 判定邏輯流程 (Process-to-Network Correlation)

```
 [WMI 程序啟動事件]          [每 N 秒輪詢 TCP/UDP × IPv4/IPv6 表]
          │                            │ (Owning PID + Local/Remote Port)
          └─────────────┬──────────────┘
                        ▼
        [PID → QueryFullProcessImageName 取執行檔路徑]
                        │
        [快取查詢：key = (PID, 程序啟動時間)]──命中──► 直接沿用結果
                        │ 未命中
                        ├─► 證據 A：Authenticode 簽章 Subject 命中名單
                        ├─► 證據 B：FileVersionInfo (OriginalFilename / ProductName / FileDescription / InternalName)
                        ├─► 證據 C：程序名稱命中名單
                        └─► 輔助 D：連線命中專用埠（單獨命中僅告警，不處置）
                        │
              [A / B / C 任一命中]
                        │
        ├─► Audit 模式：僅告警
        ├─► Enforce 模式：Kill 整個程序樹 → 停用並停止對應 Windows 服務
        ├─► [通知]：Named Pipe 推送至 Tray 氣泡
        └─► [通報]：寫入本機佇列 → 送 Server（失敗自動重送、Event Log 備援）
```

---

## 4. 自我保護與失聯偵測機制

### 4.1 防範手動終止 (Anti-Kill & Recovery)
1. **SYSTEM 權限隔離**：核心邏輯運作於 Session 0 服務，標準使用者無權終止或暫停該程序（需 `PROCESS_TERMINATE` / `PROCESS_SUSPEND_RESUME` 權限）。
2. **服務崩潰自動拉起**：
   ```cmd
   sc.exe failure CerberusAgent reset= 86400 actions= restart/1000/restart/1000/restart/5000
   sc.exe failureflag CerberusAgent 1
   ```
3. **正常停止 / 關機通報**：服務於 `OnStop` 與 `OnShutdown` 送出告警。
4. **強制結束**：`TerminateProcess` 不會執行任何清理程式碼，此情境一律由 **4.3 伺服器失聯告警** 與 **Tray 失聯回報** 涵蓋。

### 4.2 防範程序凍結 (Anti-Suspend)
* **限制**：程序被暫停時其所有線程同時停止，無法由程序自身偵測。
* **對策**：
  * Tray 與服務透過 Named Pipe 每 2 秒互發心跳。Tray 連續 10 秒收不到服務回應時，**由 Tray 直接向伺服器送出「服務無回應」告警**。
  * 伺服器端心跳逾時告警（4.3）作為最後防線。

### 4.3 防範斷網逃逸 (Dead Man's Snitch)
* Agent 每 60 秒送出 HMAC 簽章心跳（含主機名、目前使用者、Agent 版本、模式）。
* 伺服器連續 **3 分鐘** 未收到某主機心跳，主動觸發告警：「主機 `[HostName]` 監控中斷或異常離線」；恢復後再送一次「已恢復」。
* 斷網期間的違規紀錄寫入本機佇列（`%ProgramData%\Cerberus\queue`），恢復連線後補送。

---

## 5. 進階資安風險與應對矩陣

| 風險項目 | 攻擊手法 / 逃逸場景 | 系統防禦與補強措施 |
| :--- | :--- | :--- |
| **偽裝改名** | 將 `AnyDesk.exe` 改名為 `svchost.exe`。 | 比對 Authenticode 簽章與 `OriginalFilename`，不受檔名影響。 |
| **剝除簽章 + 改資源** | 移除簽章並以 Resource Hacker 修改版本資訊。 | 保留 SHA-256 雜湊黑名單欄位；搭配 WDAC / AppLocker 僅允許已簽章程式執行。 |
| **免安裝綠色版** | 自 `Temp` 或隨身碟直接執行。 | 程序啟動事件全域監控，不依賴安裝路徑。 |
| **安裝版服務自動重啟** | 被殺後 TeamViewer / AnyDesk 服務由 SCM 拉回。 | 強制模式下同時停止並將對應服務設為 `Disabled`。 |
| **內網穿透隧道** | `ngrok`、`cloudflared`、`frp`、`Tailscale`。 | 程序名稱 / 簽章特徵 + 網域封鎖。 |
| **Chrome Remote Desktop** | 安裝 CRD Host。 | 偵測 `remoting_host.exe` 並封鎖對應網域。 |
| **RustDesk 自架伺服器** | 指向自建 hbbs/hbbr，不經官方網域。 | 端點特徵偵測 + 邊界封鎖 21115–21119。 |
| **本機 RDP 開啟** | 啟用遠端桌面（Port 3389）。 | 服務定時巡檢 `fDenyTSConnections`；強制模式下自動改回 `1`。 |
| **開機進安全模式** | 繞過服務載入。 | UEFI/BIOS 密碼；服務登錄於 `SafeBoot\Network` 白名單。 |
| **管理者權限濫用** | 停用服務、改 Hosts、暫停程序。 | **收回終端使用者的本機 Administrator 權限**；伺服器失聯告警兜底。 |
| **偽造心跳** | 停掉 Agent 後以腳本假冒心跳。 | 心跳以每台主機獨立金鑰做 HMAC 簽章，並驗證時間戳（±5 分鐘）防重放。 |

---

## 6. 實作對照

| 專案 | 類型 | 主要檔案 |
| :--- | :--- | :--- |
| `Cerberus.Shared` | 類別庫 | `CerberusOptions.cs`（設定）、`Messages.cs`（告警 / 心跳 / IPC 合約）、`HmacSigner.cs` |
| `Cerberus.Agent` | Worker Service | `NativeMethods.cs`、`ConnectionTable.cs`、`ProcessInspector.cs`、`ProcessStartWatcher.cs`、`DetectionWorker.cs`、`Enforcer.cs`、`AlertQueue.cs`、`HeartbeatWorker.cs`、`RdpGuard.cs`、`PipeServer.cs`、`SessionUser.cs` |
| `Cerberus.Tray` | WPF 系統匣 | `App.xaml.cs`、`PipeClient.cs` |
| `Cerberus.Server` | ASP.NET Core Minimal API | `Program.cs`、`HostRegistry.cs`、`OfflineMonitor.cs`、`WebhookForwarder.cs` |

設定檔：`%ProgramData%\Cerberus\cerberus.json`（Agent）、`appsettings.json`（Server）。

---

## 7. 部署與落地維運計畫

### 7.1 階段部署步驟
1. **階段一：網路邊界規則套用**（2.1–2.3、DoH 原則）。
2. **階段二：端點 Agent 稽核模式**（`Mode = Audit`，建議 2 週）
   * 透過 GPO / Intune 派送，執行 `install.cmd` 安裝服務、設定失敗復原、Tray 開機啟動。
   * 收集告警，校正誤判與簽章名單。
3. **階段三：切換強制模式**（`Mode = Enforce`）。
4. **階段四：監控與心跳驗證**：確認 Server 失聯告警與 Webhook 轉發正常。

### 7.2 建議維護與更新
* **特徵庫更新**：`cerberus.json` 由集中派送，Agent 偵測檔案變更後自動重新載入。
* **簽章名單驗證**：新版本遠端工具上線時，以 `Get-AuthenticodeSignature` 確認 Subject 再更新名單。
* **白名單管理**：IT 合規需求以 `AllowedHosts` 依主機名稱排除，不提供本機端關閉開關。

---

## 8. 附錄：校正工具特徵名單（簽章 Subject 驗證）

### 8.1 為什麼要做
Agent 以三類證據辨識遠端工具：**數位簽章發行者（Authenticode Subject）**、**檔案版本資訊**、**SHA-256**。其中簽章最可靠——改檔名騙不過它。但各廠商的發行者字串不同，且會隨公司改名變動（例：AnyDesk 早期簽章為 `philandro Software GmbH`，之後為 `AnyDesk Software GmbH`）。因此 `cerberus.json` 內的 `Signers` 名單**上線前須以實際安裝檔核對一次**，否則 Enforce 模式可能漏抓。

### 8.2 用 Inspect-Signature.ps1 校正
專案附帶 `tools\Inspect-Signature.ps1`，讀出一支執行檔的簽章 Subject、版本資訊與 SHA-256，格式直接對應 `cerberus.json` 欄位。

```powershell
cd <repo>\src\Cerberus\tools

# 單一檔案
.\Inspect-Signature.ps1 "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"

# 或掃整個安裝資料夾（遞迴找 .exe）
.\Inspect-Signature.ps1 "C:\Program Files (x86)\AnyDesk"
```

輸出欄位與設定對照：

| 腳本輸出欄位 | 填入 `cerberus.json` | 說明 |
| :--- | :--- | :--- |
| `SignerCN` | `Signers` | **僅當 `SignatureStatus = Valid`** 才可信；填 `CN=` 內容片段即可 |
| `ProcessName` / `OriginalFilename` / `ProductName` / `FileDescription` | `Names` | 任選一個具辨識度的字串（程式以「包含」比對，不分大小寫） |
| `Sha256` | `Sha256` | 僅在需鎖定特定變種（如剝除簽章的綠色版）時才填 |

### 8.3 沒有安裝檔可核對時
若手邊無法取得某工具的安裝檔，**先以 Audit 模式上線**：Audit 只告警不處置，每筆偵測告警都會記錄命中的簽章 Subject。據此可從真實告警反推正確字串，回填名單後再切 Enforce——這也是 §7.1 要求「先 Audit 兩週」的原因之一。

一句話：**有軟體 → 用腳本現場校正；沒軟體 → 先 Audit，讓系統把正確值報回來。**
