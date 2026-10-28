<#
.SYNOPSIS
  為單一端點產生專屬 HMAC 金鑰，並輸出 Agent 端與 Server 端的設定片段。

.DESCRIPTION
  Cerberus 預設可用共用金鑰（DefaultKey），但一台外洩即全體淪陷。
  正式環境應「每台一把」：用本工具為每台主機產生亂數金鑰，
  Agent 端寫入該機的 cerberus.json，Server 端加進 HostKeys。

.PARAMETER HostName
  目標主機名稱（對應 Server HostKeys 的鍵）。預設為本機名稱。

.PARAMETER ConfigPath
  指定後，直接把產生的金鑰寫入該 cerberus.json 的 HostKey 欄位。

.EXAMPLE
  .\New-HostKey.ps1 -HostName PC-01
  # 產生金鑰並印出兩端設定片段

.EXAMPLE
  .\New-HostKey.ps1 -ConfigPath C:\ProgramData\Cerberus\cerberus.json
  # 產生金鑰並直接寫入本機 Agent 設定
#>
[CmdletBinding()]
param(
    [string]$HostName = $env:COMPUTERNAME,
    [string]$ConfigPath
)

# 32 bytes 高強度亂數 → Base64
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$key = [Convert]::ToBase64String($bytes)

Write-Host "===== 已為主機 '$HostName' 產生金鑰 =====" -ForegroundColor Cyan
Write-Host ""
Write-Host "Agent 端（該機 cerberus.json 的 Cerberus 區段）：" -ForegroundColor Yellow
Write-Host "  `"HostKey`": `"$key`""
Write-Host ""
Write-Host "Server 端（appsettings.json 的 Cerberus:HostKeys）：" -ForegroundColor Yellow
Write-Host "  `"$HostName`": `"$key`""
Write-Host ""

if ($ConfigPath) {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Write-Error "找不到設定檔：$ConfigPath"
        exit 1
    }
    try {
        $json = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        if (-not $json.Cerberus) { throw "設定檔缺少 Cerberus 區段" }
        $json.Cerberus.HostKey = $key
        ($json | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $ConfigPath -Encoding utf8
        Write-Host "已寫入 Agent 設定：$ConfigPath（存檔後 Agent 會自動熱重載）" -ForegroundColor Green
    }
    catch {
        Write-Error "寫入失敗：$($_.Exception.Message)"
        exit 1
    }
}

Write-Host "提醒：正式環境請把 Server 的 DefaultKey 留空，未註冊於 HostKeys 的主機一律拒絕。" -ForegroundColor DarkYellow
