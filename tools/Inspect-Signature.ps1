<#
.SYNOPSIS
  檢視執行檔的數位簽章發行者、版本資訊與 SHA-256，用來校正 cerberus.json 的特徵名單。

.DESCRIPTION
  cerberus.json 以「簽章 Subject / 版本資訊 / SHA-256」辨識遠端控制工具。
  本腳本讀出這些欄位，讓你用「真正的安裝檔」核對後再填入設定，避免漏抓或誤判。

.PARAMETER Path
  要檢視的 .exe 檔，或包含多個 .exe 的資料夾（會遞迴）。

.EXAMPLE
  .\Inspect-Signature.ps1 "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"

.EXAMPLE
  # 掃描整個安裝資料夾，挑出有簽章的執行檔
  .\Inspect-Signature.ps1 "C:\Program Files (x86)\AnyDesk"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path
)

function Inspect-One {
    param([string]$File)

    $sig = Get-AuthenticodeSignature -LiteralPath $File
    $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File)

    # CN= 片段：這就是要填進 cerberus.json "Signers" 的值
    $subject = $sig.SignerCertificate.Subject
    $cn = if ($subject -match 'CN="?([^",]+)"?') { $matches[1] } else { $null }

    [PSCustomObject]@{
        File             = Split-Path $File -Leaf
        FullPath         = $File
        SignatureStatus  = $sig.Status                       # Valid 才是有效簽章
        SignerCN         = $cn                               # -> Signers
        Subject          = $subject
        ProcessName      = [IO.Path]::GetFileNameWithoutExtension($File)  # -> Names
        OriginalFilename = $ver.OriginalFilename             # -> Names
        ProductName      = $ver.ProductName                  # -> Names
        FileDescription  = $ver.FileDescription              # -> Names
        Sha256           = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash  # -> Sha256
    }
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "找不到路徑：$Path"
    exit 1
}

$item = Get-Item -LiteralPath $Path
$files = if ($item.PSIsContainer) {
    Get-ChildItem -LiteralPath $Path -Recurse -Filter *.exe -File |
        Select-Object -ExpandProperty FullName
} else {
    @($item.FullName)
}

if (-not $files) {
    Write-Warning "沒有找到 .exe 檔。"
    exit 0
}

$results = foreach ($f in $files) {
    try { Inspect-One -File $f }
    catch { Write-Warning "讀取失敗 $f：$($_.Exception.Message)" }
}

# 逐檔明細
$results | Format-List File, SignatureStatus, SignerCN, ProcessName, OriginalFilename, ProductName, FileDescription, Sha256

Write-Host ""
Write-Host "=== 對照 cerberus.json 填法 ===" -ForegroundColor Cyan
Write-Host 'Signers <- SignerCN（只有 SignatureStatus = Valid 時才可信）'
Write-Host 'Names   <- ProcessName / OriginalFilename / ProductName / FileDescription 任一具辨識度的字串'
Write-Host 'Sha256  <- 僅在需要鎖定特定變種（例如剝除簽章的綠色版）時才填'
