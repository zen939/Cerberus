using System.Runtime.InteropServices;

namespace Cerberus.Agent;

/// <summary>服務以 SYSTEM 執行，Environment.UserName 永遠是 SYSTEM，改向 WTS 查詢實際登入者。</summary>
public static class SessionUser
{
    public static string? ForSession(int sessionId)
    {
        var user = Query(sessionId, NativeMethods.WTS_INFO_CLASS.WTSUserName);
        if (string.IsNullOrEmpty(user))
            return null;

        var domain = Query(sessionId, NativeMethods.WTS_INFO_CLASS.WTSDomainName);
        return string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}";
    }

    public static string? ForConsole()
    {
        int sessionId = NativeMethods.WTSGetActiveConsoleSessionId();
        return sessionId == -1 ? null : ForSession(sessionId);
    }

    private static string? Query(int sessionId, NativeMethods.WTS_INFO_CLASS infoClass)
    {
        if (!NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;

        try { return Marshal.PtrToStringUni(buffer); }
        finally { NativeMethods.WTSFreeMemory(buffer); }
    }
}
