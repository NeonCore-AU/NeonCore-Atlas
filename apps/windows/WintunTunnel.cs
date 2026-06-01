using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NeonCore.Atlas;

public sealed class WintunTunnel : IDisposable
{
    private readonly PacketClassifier classifier = new();
    private CancellationTokenSource? cancellation;

    public bool IsRunning => cancellation is not null;

    public Task StartAsync(CancellationToken token = default)
    {
        if (cancellation is not null) return Task.CompletedTask;
        cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        return Task.Run(() => PacketLoop(cancellation.Token), CancellationToken.None);
    }

    public void Stop()
    {
        cancellation?.Cancel();
        cancellation = null;
    }

    public void Dispose() => Stop();

    private void PacketLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            Thread.Sleep(50);
        }
    }

    public PacketDecision InspectPacket(ReadOnlySpan<byte> packet)
    {
        return classifier.Classify(packet);
    }
}

public enum PacketDecision
{
    Tcp,
    Udp,
    Dns,
    Drop
}

public sealed class PacketClassifier
{
    public PacketDecision Classify(ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty) return PacketDecision.Drop;
        return packet[0] >> 4 switch
        {
            4 => ClassifyIpv4(packet),
            6 => ClassifyIpv6(packet),
            _ => PacketDecision.Drop
        };
    }

    private static PacketDecision ClassifyIpv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20) return PacketDecision.Drop;
        var headerLength = (packet[0] & 0x0f) * 4;
        if (headerLength < 20 || packet.Length < headerLength) return PacketDecision.Drop;
        return ClassifyTransport(packet[9], packet[headerLength..]);
    }

    private static PacketDecision ClassifyIpv6(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 40) return PacketDecision.Drop;
        return ClassifyTransport(packet[6], packet[40..]);
    }

    private static PacketDecision ClassifyTransport(byte protocolNumber, ReadOnlySpan<byte> payload)
    {
        return protocolNumber switch
        {
            6 => PacketDecision.Tcp,
            17 when payload.Length >= 8 && ((payload[2] << 8) | payload[3]) == 53 => PacketDecision.Dns,
            17 => PacketDecision.Udp,
            _ => PacketDecision.Drop
        };
    }
}

internal static partial class WintunNative
{
    [LibraryImport("wintun.dll", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr requestedGuid);

    [LibraryImport("wintun.dll")]
    internal static partial void WintunCloseAdapter(IntPtr adapter);

    internal static void ThrowIfMissing()
    {
        if (!NativeLibrary.TryLoad("wintun.dll", out var handle))
        {
            throw new Win32Exception("wintun.dll is not available");
        }
        NativeLibrary.Free(handle);
    }
}
