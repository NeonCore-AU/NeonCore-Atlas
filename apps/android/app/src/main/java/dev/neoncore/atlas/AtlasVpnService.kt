package dev.neoncore.atlas

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

class AtlasVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var packetThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val classifier = PacketClassifier()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startTunnel()
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun startTunnel() {
        if (running.getAndSet(true)) return
        tunnel = Builder()
            .setSession("NeonCore")
            .setMtu(1500)
            .addAddress("198.18.0.2", 24)
            .addAddress("fd7a:115c:a1e0::2", 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("198.18.0.1")
            .addDnsServer("fd7a:115c:a1e0::1")
            .establish()
        val descriptor = tunnel?.fileDescriptor ?: return
        packetThread = Thread {
            FileInputStream(descriptor).use { input ->
                val buffer = ByteArray(32767)
                while (running.get()) {
                    val length = input.read(buffer)
                    if (length <= 0) continue
                    when (classifier.classify(buffer, length)) {
                        PacketDecision.TCP -> handleTcp(buffer, length)
                        PacketDecision.UDP -> handleUdp(buffer, length)
                        PacketDecision.DNS -> handleDns(buffer, length)
                        PacketDecision.DROP -> Unit
                    }
                }
            }
        }.also {
            it.name = "NeonCoreVpnPacketLoop"
            it.start()
        }
    }

    private fun stopTunnel() {
        running.set(false)
        tunnel?.close()
        tunnel = null
        packetThread = null
    }

    private fun handleTcp(packet: ByteArray, length: Int) {
        if (length == 0) return
    }

    private fun handleUdp(packet: ByteArray, length: Int) {
        if (length == 0) return
    }

    private fun handleDns(packet: ByteArray, length: Int) {
        if (length == 0) return
    }
}

private enum class PacketDecision {
    TCP,
    UDP,
    DNS,
    DROP
}

private class PacketClassifier {
    fun classify(packet: ByteArray, length: Int): PacketDecision {
        if (length < 1) return PacketDecision.DROP
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> classifyIPv4(packet, length)
            6 -> classifyIPv6(packet, length)
            else -> PacketDecision.DROP
        }
    }

    private fun classifyIPv4(packet: ByteArray, length: Int): PacketDecision {
        if (length < 20) return PacketDecision.DROP
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < 20 || length < headerLength) return PacketDecision.DROP
        return classifyTransport(packet[9].toInt() and 0xff, packet, headerLength, length)
    }

    private fun classifyIPv6(packet: ByteArray, length: Int): PacketDecision {
        if (length < 40) return PacketDecision.DROP
        return classifyTransport(packet[6].toInt() and 0xff, packet, 40, length)
    }

    private fun classifyTransport(protocolNumber: Int, packet: ByteArray, offset: Int, length: Int): PacketDecision {
        return when (protocolNumber) {
            6 -> PacketDecision.TCP
            17 -> {
                if (length < offset + 8) return PacketDecision.DROP
                val destinationPort = ((packet[offset + 2].toInt() and 0xff) shl 8) or (packet[offset + 3].toInt() and 0xff)
                if (destinationPort == 53) PacketDecision.DNS else PacketDecision.UDP
            }
            else -> PacketDecision.DROP
        }
    }
}
