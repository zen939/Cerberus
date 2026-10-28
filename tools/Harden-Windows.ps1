<#
.SYNOPSIS
  Windows 端點資安強化快速設定腳本（與 Cerberus 端點守護搭配使用）。

.DESCRIPTION
  檢查並（選用）套用一組常見的端點強化基準：Windows Defender、防火牆、
  遠端桌面、SMBv1、AutoRun、PowerShell 稽核記錄、LSA 保護、Guest 存取等。

  安全設計：
    - 預設為「稽核模式」，只report目前狀態與「會做什麼」，不改動系統。
    - 加上 -Apply 才會實際套用變更。
    - 每一項都獨立，可用 -Only 挑選；全程輸出動作紀錄。

  須以系統管理員身分執行。部分項目（SMBv1、LSA 保護）需重開機生效。

.PARAMETER Apply
  實際套用變更。省略則僅稽核。

.PARAMETER Only
  只處理指定項目（逗號分隔）。可用值：
  Defender, Firewall, Rdp, Smb1, AutoRun, PsLogging, Lsa, GuestAccess, DefenderScan

.EXAMPLE
  .\Harden-Windows.ps1
  # 稽核模式：列出目前狀態與建議，不改動

.EXAMPLE
  .\Harden-Windows.ps1 -Apply
  # 套用全部強化項目

.EXAMPLE
  .\Harden-Windows.ps1 -Apply -Only Defender,Firewall,DefenderScan
  # 只開 Defender、防火牆並立即掃毒
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$script:changes = 0

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Should-Run([string]$name) {
    (-not $Only) -or ($Only -contains $name)
}

# 統一輸出：report 現況，Apply 時執行 $action
function Step {
    param(
        [string]$Name,
        [string]$Desc,
        [scriptblock]$Current,   # 傳回目前狀態字串
        [scriptblock]$NeedsFix,  # 傳回 $true 表示需要處理
        [scriptblock]$Action     # Apply 時執行
    )
    if (-not (Should-Run $Name)) { return }

    Write-Host ""
    Write-Host ("[{0}] {1}" -f $Name, $Desc) -ForegroundColor Cyan
    try {
        $state = & $Current
        $needs = & $NeedsFix
        Write-Host ("  現況: {0}" -f $state)
        if (-not $needs) {
            Write-Host "  OK，無需變更" -ForegroundColor Green
            return
        }
        if ($Apply) {
            & $Action
            $script:changes++
            Write-Host "  已套用變更" -ForegroundColor Yellow
        } else {
            Write-Host "  [建議] 加 -Apply 可套用此強化" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host ("  略過（無法處理）: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
    }
}

# ---- 前置 ----
if (-not (Test-Admin)) {
    Write-Error "請以系統管理員身分執行。"
    exit 1
}

Write-Host "===== Cerberus Windows 強化腳本 =====" -ForegroundColor White
Write-Host ("模式: {0}" -f $(if ($Apply) { '套用 (Apply)' } else { '稽核 (僅report)' }))

# 1) Windows Defender 即時保護
Step -Name Defender -Desc "Windows Defender 即時保護" `
    -Current { $s = Get-MpPreference; "即時監控停用=$($s.DisableRealtimeMonitoring)" } `
    -NeedsFix { (Get-MpPreference).DisableRealtimeMonitoring } `
    -Action { Set-MpPreference -DisableRealtimeMonitoring $false }

# 2) 防火牆三設定檔
Step -Name Firewall -Desc "Windows 防火牆（Domain/Private/Public）" `
    -Current { ((Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ') } `
    -NeedsFix { (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -gt 0 } `
    -Action { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True }

# 3) 遠端桌面（預設關閉）
Step -Name Rdp -Desc "停用遠端桌面 (fDenyTSConnections=1)" `
    -Current {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
        "fDenyTSConnections=$v"
    } `
    -NeedsFix {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections -ne 1
    } `
    -Action { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord }

# 4) 停用 SMBv1（已知高風險協定）
Step -Name Smb1 -Desc "停用 SMBv1 用戶端/伺服器（需重開機）" `
    -Current { "SMB1 Server=$((Get-SmbServerConfiguration).EnableSMB1Protocol)" } `
    -NeedsFix { (Get-SmbServerConfiguration).EnableSMB1Protocol } `
    -Action {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -EA SilentlyContinue | Out-Null
    }

# 5) 停用 AutoRun/AutoPlay（隨身碟惡意程式常見途徑）
Step -Name AutoRun -Desc "停用所有磁碟 AutoRun (NoDriveTypeAutoRun=0xFF)" `
    -Current {
        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun
        "NoDriveTypeAutoRun=$v"
    } `
    -NeedsFix {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun -ne 255
    } `
    -Action {
        New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord
    }

# 6) PowerShell ScriptBlock 稽核記錄（事後鑑識用）
Step -Name PsLogging -Desc "啟用 PowerShell ScriptBlock Logging" `
    -Current {
        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging
        "EnableScriptBlockLogging=$v"
    } `
    -NeedsFix {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging -ne 1
    } `
    -Action {
        New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
        Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
    }

# 7) LSA 保護 RunAsPPL（防 LSASS 憑證竊取，需重開機）
Step -Name Lsa -Desc "啟用 LSA 保護 RunAsPPL（需重開機）" `
    -Current {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
        "RunAsPPL=$v"
    } `
    -NeedsFix {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL -ne 1
    } `
    -Action { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord }

# 8) 停用 SMB Guest 匿名存取
Step -Name GuestAccess -Desc "停用 SMB 不安全的 Guest 登入" `
    -Current {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -EA SilentlyContinue).AllowInsecureGuestAuth
        "AllowInsecureGuestAuth=$v"
    } `
    -NeedsFix {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -EA SilentlyContinue).AllowInsecureGuestAuth -ne 0
    } `
    -Action {
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Force | Out-Null
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord
    }

# 9) 更新病毒定義並執行快速掃描（此項僅在 Apply 時動作）
Step -Name DefenderScan -Desc "更新 Defender 定義並執行快速掃描" `
    -Current {
        $s = Get-MpComputerStatus
        "定義版本=$($s.AntivirusSignatureVersion), 上次快掃=$($s.QuickScanEndTime)"
    } `
    -NeedsFix { $true } `
    -Action {
        Write-Host "  更新病毒定義..." -ForegroundColor DarkGray
        Update-MpSignature -EA SilentlyContinue
        Write-Host "  執行快速掃描（可能需數分鐘）..." -ForegroundColor DarkGray
        Start-MpScan -ScanType QuickScan
    }

# ---- 總結 ----
Write-Host ""
Write-Host "===== 完成 =====" -ForegroundColor White
if ($Apply) {
    Write-Host ("套用了 {0} 項變更。" -f $script:changes)
    Write-Host "注意：SMBv1 與 LSA 保護需「重新開機」才會生效。" -ForegroundColor Yellow
} else {
    Write-Host "目前為稽核模式，未改動任何設定。加 -Apply 才會套用。"
}
