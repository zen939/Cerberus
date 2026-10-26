using System.Runtime.InteropServices;
using System.Text;

namespace Cerberus.Agent;

internal static partial class NativeMethods
{
    public const int AF_INET = 2;
    public const int AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;
    public const uint NO_ERROR = 0;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [LibraryImport("iphlpapi.dll")]
    public static partial uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    public static partial uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial IntPtr OpenProcess(
        uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    public enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSDomainName = 7
    }

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSQuerySessionInformation(
        IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("kernel32.dll")]
    public static extern int WTSGetActiveConsoleSessionId();

    /// <summary>以 PROCESS_QUERY_LIMITED_INFORMATION 取完整路徑，32/64 位元皆可用，比 Process.MainModule 輕量。</summary>
    public static string? GetProcessImagePath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
            return null;

        try
        {
            var buffer = new StringBuilder(1024);
            int size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
