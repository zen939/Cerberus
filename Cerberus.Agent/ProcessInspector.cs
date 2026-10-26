using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Shared;
using Microsoft.Extensions.Options;

namespace Cerberus.Agent;

public sealed record DetectionHit(ToolSignature Tool, string Evidence);

/// <summary>
/// 依執行檔判定是否為遠端工具。讀簽章與雜湊很耗時，
/// 結果以 (路徑, 修改時間, 大小) 快取；設定檔變更時清空。
/// </summary>
public sealed class ProcessInspector
{
    private readonly record struct FileKey(string Path, DateTime LastWriteUtc, long Length);

    private readonly ConcurrentDictionary<FileKey, DetectionHit?> _cache = new();
    private readonly IOptionsMonitor<CerberusOptions> _options;
    private readonly ILogger<ProcessInspector> _logger;

    public ProcessInspector(IOptionsMonitor<CerberusOptions> options, ILogger<ProcessInspector> logger)
    {
        _options = options;
        _logger = logger;
        _options.OnChange(_ => _cache.Clear());
    }

    public DetectionHit? Inspect(string processName, string filePath)
    {
        var tools = _options.CurrentValue.Tools;

        // 程序名稱不需讀檔，先比
        foreach (var tool in tools)
        {
            var name = FirstContained(processName, tool.Names);
            if (name is not null)
                return new DetectionHit(tool, $"程序名稱含「{name}」");
        }

        FileKey key;
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists)
                return null;
            key = new FileKey(filePath, info.LastWriteTimeUtc, info.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return _cache.GetOrAdd(key, k => InspectFile(k.Path, tools));
    }

    private DetectionHit? InspectFile(string filePath, List<ToolSignature> tools)
    {
        // 證據 A：Authenticode 簽章發行者（改名無效）
        var subject = ReadSignerSubject(filePath);
        if (subject is not null)
        {
            foreach (var tool in tools)
            {
                var signer = FirstContained(subject, tool.Signers);
                if (signer is not null)
                    return new DetectionHit(tool, $"數位簽章發行者含「{signer}」");
            }
        }

        // 證據 B：版本資源
        try
        {
            var version = FileVersionInfo.GetVersionInfo(filePath);
            string[] fields =
            [
                version.OriginalFilename ?? string.Empty,
                version.ProductName ?? string.Empty,
                version.FileDescription ?? string.Empty,
                version.InternalName ?? string.Empty
            ];

            foreach (var tool in tools)
            {
                foreach (var field in fields)
                {
                    var name = FirstContained(field, tool.Names);
                    if (name is not null)
                        return new DetectionHit(tool, $"檔案版本資訊「{field}」含「{name}」");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "無法讀取版本資訊 {Path}", filePath);
        }

        // 證據 C：雜湊黑名單（有設定才計算）
        if (tools.Any(t => t.Sha256.Count > 0))
        {
            var hash = ComputeSha256(filePath);
            if (hash is not null)
            {
                foreach (var tool in tools)
                {
                    if (tool.Sha256.Contains(hash, StringComparer.OrdinalIgnoreCase))
                        return new DetectionHit(tool, $"SHA-256 命中 {hash}");
                }
            }
        }

        return null;
    }

    /// <summary>
    /// 只讀取嵌入的簽署者憑證，不驗證信任鏈：此處用於比對黑名單，
    /// 偽造「TeamViewer」簽章只會讓自己被擋，沒有繞過的價值。
    /// </summary>
    private static string? ReadSignerSubject(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (CryptographicException)
        {
            return null; // 未簽章
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? ComputeSha256(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? FirstContained(string text, List<string> needles)
    {
        if (string.IsNullOrEmpty(text))
            return null;

        foreach (var needle in needles)
        {
            if (!string.IsNullOrWhiteSpace(needle) && text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return needle;
        }
        return null;
    }
}
