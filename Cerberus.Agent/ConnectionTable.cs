using System.Runtime.InteropServices;

namespace Cerberus.Agent;

public enum TransportProtocol { Tcp, Udp }

public readonly record struct ConnectionEntry(int Pid, TransportProtocol Protocol, ushort LocalPort, ushort RemotePort);

/// <summary>
/// 讀取 TCP / UDP × IPv4 / IPv6 的連線表與擁有者 PID。
/// 各列結構只含 DWORD 與 byte 陣列，直接以位移讀取，避免 struct 對齊問題：
/// MIB_TCPROW_OWNER_PID   24 bytes：state, localAddr, localPort, remoteAddr, remotePort, pid
/// MIB_TCP6ROW_OWNER_PID  56 bytes：localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid
/// MIB_UDPROW_OWNER_PID   12 bytes：localAddr, localPort, pid
/// MIB_UDP6ROW_OWNER_PID  28 bytes：localAddr[16], scope, localPort, pid
/// </summary>
public static class ConnectionTable
{
    public static List<ConnectionEntry> Read()
    {
        var result = new List<ConnectionEntry>(512);

        ReadTable(isTcp: true, NativeMethods.AF_INET, rowSize: 24, (row, list) =>
            list.Add(new(Marshal.ReadInt32(row, 20), TransportProtocol.Tcp, Port(row, 8), Port(row, 16))), result);

        ReadTable(isTcp: true, NativeMethods.AF_INET6, rowSize: 56, (row, list) =>
            list.Add(new(Marshal.ReadInt32(row, 52), TransportProtocol.Tcp, Port(row, 20), Port(row, 44))), result);

        ReadTable(isTcp: false, NativeMethods.AF_INET, rowSize: 12, (row, list) =>
            list.Add(new(Marshal.ReadInt32(row, 8), TransportProtocol.Udp, Port(row, 4), 0)), result);

        ReadTable(isTcp: false, NativeMethods.AF_INET6, rowSize: 28, (row, list) =>
            list.Add(new(Marshal.ReadInt32(row, 24), TransportProtocol.Udp, Port(row, 20), 0)), result);

        return result;
    }

    // 連接埠以網路位元組序存在 DWORD 的低 16 位元
    private static ushort Port(IntPtr row, int offset)
    {
        uint v = (uint)Marshal.ReadInt32(row, offset);
        return (ushort)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
    }

    private static void ReadTable(bool isTcp, int family, int rowSize,
        Action<IntPtr, List<ConnectionEntry>> parseRow, List<ConnectionEntry> output)
    {
        int size = 0;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            // 兩次呼叫之間表可能變大，重試幾次
            for (int attempt = 0; attempt < 5; attempt++)
            {
                uint rc = isTcp
                    ? NativeMethods.GetExtendedTcpTable(buffer, ref size, false, family, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0)
                    : NativeMethods.GetExtendedUdpTable(buffer, ref size, false, family, NativeMethods.UDP_TABLE_OWNER_PID, 0);

                if (rc == NativeMethods.NO_ERROR && buffer != IntPtr.Zero)
                {
                    int count = Marshal.ReadInt32(buffer);
                    for (int i = 0; i < count; i++)
                        parseRow(buffer + 4 + i * rowSize, output);
                    return;
                }

                if (rc != NativeMethods.ERROR_INSUFFICIENT_BUFFER)
                    return;

                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal(size);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }
}
