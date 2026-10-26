<#
.SYNOPSIS
  產生 Cerberus Server 的 TLS 自簽憑證（PFX + CER），並印出指紋供 Agent 釘選。

.DESCRIPTION
  輸出到 certs\ 資料夾：
    cerberus.pfx  含私鑰，掛載進容器給 Kestrel 使用（切勿進版控）
    cerberus.cer  公開憑證，可透過 GPO 派送到端點信任存放區（選用）
  並印出 SHA-1 指紋，填入各 Agent 的 cerberus.json "ServerCertThumbprint"。
  正式環境建議改用企業 CA 簽發的憑證。

.PARAMETER DnsNames
  憑證的 DNS 名稱（Server 對外網址的主機名）。預設 localhost 與本機名稱。

.PARAMETER Password
  PFX 匯出密碼。預設隨機產生並印出。

.EXAMPLE
  .\New-ServerCert.ps1 -DnsNames cerberus.corp.local,localhost
#>
[CmdletBinding()]
param(
    [string[]]$DnsNames = @('localhost', $env:COMPUTERNAME),
    [string]$Password
)

$outDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'certs'
New-Item -ItemType Directory -Force $outDir | Out-Null

if (-not $Password) {
    $bytes = New-Object byte[] 18
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $Password = [Convert]::ToBase64String($bytes)
}

Write-Host "產生自簽憑證，DNS: $($DnsNames -join ', ')" -ForegroundColor Cyan
$cert = New-SelfSignedCertificate `
    -DnsName $DnsNames `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -FriendlyName 'Cerberus Server' `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(3)

$pfx = Join-Path $outDir 'cerberus.pfx'
$cer = Join-Path $outDir 'cerberus.cer'
$secure = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null
Export-Certificate   -Cert $cert -FilePath $cer | Out-Null

# 從存放區移除（檔案已匯出，不需常駐）
Remove-Item ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force

Write-Host ""
Write-Host "PFX（掛載給容器）: $pfx" -ForegroundColor Green
Write-Host "CER（派送信任）  : $cer" -ForegroundColor Green
Write-Host ("PFX 密碼         : {0}" -f $Password) -ForegroundColor Yellow
Write-Host ""
Write-Host "Server 端（docker-compose.tls.yml 或環境變數）：" -ForegroundColor Yellow
Write-Host "  CERBERUS_CERT_PASSWORD=$Password"
Write-Host ""
Write-Host "Agent 端（各機 cerberus.json 的 Cerberus 區段）：" -ForegroundColor Yellow
Write-Host ("  `"ServerUrl`": `"https://<server 主機>:8443`",")
Write-Host ("  `"ServerCertThumbprint`": `"{0}`"" -f $cert.Thumbprint)
Write-Host ""
Write-Host "注意：certs\ 內含私鑰，已被 .gitignore 排除，切勿進版控或外流。" -ForegroundColor DarkYellow
