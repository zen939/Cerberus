Cerberus 端點守護 — 本機測試安裝說明
=====================================

內容物
------
  Cerberus.Agent.exe   核心守護服務（以 SYSTEM 執行，偵測/處置）
  Cerberus.Tray.exe    系統匣 UI（氣泡通知、狀態顯示）
  cerberus.json        設定檔（預設複製到 %ProgramData%\Cerberus\）
  install.cmd          安裝（建立服務 + 登錄 Tray 開機啟動）
  uninstall.cmd        移除

先決條件
--------
  - Windows 10/11 x64
  - 本安裝檔為 self-contained，目標機「不需」預先安裝 .NET。
  - 安裝與移除都必須「以系統管理員身分執行」。

安裝步驟（本機測試）
--------------------
  1. 在本資料夾空白處按右鍵 →「在終端中開啟」，或開啟「系統管理員命令提示字元」。
  2. 執行：install.cmd
     （若被 SmartScreen 攔，點「其他資訊」→「仍要執行」；這是未簽章執行檔的正常提示。）
  3. 安裝後：
       - 服務 CerberusAgent 會啟動（可在「服務」管理員看到）。
       - 右下角系統匣出現盾牌圖示。
       - 預設為 Audit（僅告警）模式，不會終止任何程式。

驗證是否運作
------------
  - 開啟「事件檢視器 → Windows 記錄 → 應用程式」，來源 CerberusAgent 會記錄偵測告警。
  - 或裝一套 AnyDesk/TeamViewer 測試：Audit 模式下系統匣會跳氣泡通知，但不會被終止。

連線到 Server（選用）
---------------------
  編輯 %ProgramData%\Cerberus\cerberus.json：
    "ServerUrl": "http://<伺服器IP>:8080"
    "HostKey":   "<與 Server DefaultKey 或該主機 HostKeys 相同的字串>"
  存檔後設定會自動熱重載，無需重啟服務。

切換為強制模式
--------------
  確認 Audit 模式無誤判後，將 cerberus.json 的 "Mode" 改為 "Enforce"。
  Enforce 會終止偵測到的遠端工具程序並停用其服務，請務必先完成簽章名單校正
  （見 tools\Inspect-Signature.ps1 與規劃書 §8）。

移除
----
  以系統管理員執行：uninstall.cmd
