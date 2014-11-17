package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.pcap.Device;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.pcap.PcapDumper;
import de.rub.nds.virtualnetworklayer.pcap.PcapHandler;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;

import static junit.framework.Assert.*;

public class PcapTest {
    private static int count;

    @Before
    public void setUp() {
        count = 0;
    }

    @Test
    public void version() {
        assertTrue(Pcap.getVersion().startsWith("libpcap version"));
    }

    @Test
    public void devices() {
        List<Device> devices = Pcap.getDevices();
        assertTrue(devices.size() > 0);
    }

    @Test
    public void liveDevice() {
        Device device = Pcap.getLiveDevice();
        assertNotNull(device);
    }

    @Test
    public void defaultDevice() {
        Device device = Pcap.getDefaultDevice();
        assertNotNull(device);
    }

    @Test
    public void pcapHandler() {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        Pcap.Status status = pcap.loop(new PcapHandler() {
            @Override
            public void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
                count++;
            }
        });

        assertEquals(Pcap.Status.Success, status);
        assertEquals(137, count);
    }

    @Test
    public void pcapHandlerAsynchronous() {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        pcap.loopAsynchronous(new PcapHandler() {
            @Override
            public void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
                count++;
            }
        });

        pcap.breakloop();

        assertNotSame(137, count);
        assertEquals(Pcap.Status.Terminated, pcap.getStatus());
    }


    @Test(expected = IllegalArgumentException.class)
    public void filterParsingError() {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);
        pcap.filter("scr host 192.168.1.58");
    }

    @Test
    public void filter() {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);
        pcap.filter("src host 192.168.1.58 and tcp port 49182");

        pcap.loop(new PcapHandler() {
            @Override
            public void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
                count++;
            }
        });

        assertEquals(14, count);
    }

    @Test
    public void dumper() throws IOException {
        File file = new File(getClass().getResource("httpsGoogle.pcap").getPath());
        Pcap pcap = Pcap.openOffline(file);

        Path tempDump = Files.createTempFile("", ".pcap");
        final PcapDumper dumper = pcap.openDump(tempDump.toFile());
        final long initialPosition = dumper.position();

        // loop over file: dump all data, and save it to compare later

        class PacketData {
            long timestamp;
            int length;
            ByteBuffer bytes;
        }
        final List<PacketData> allPacketData = new LinkedList<>();

        pcap.loop(new PcapHandler() {
            @Override
            protected void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
                RawPacket rawPacket = getCurrentRawPacket();
                dumper.dump(rawPacket);

                // save java-layer data to compare it later
                PacketData packet = new PacketData();
                packet.timestamp = timeStamp;
                packet.length = length;
                byteBuffer.rewind();
                packet.bytes = ByteBuffer.allocateDirect(byteBuffer.capacity());
                packet.bytes.put(byteBuffer.asReadOnlyBuffer()).rewind();
                allPacketData.add(packet);
            }
        });

        assertTrue(dumper.position() > initialPosition);
        dumper.flush(); // probably not necessary - but at least we test it here
        dumper.close();

        // now dump over dumpfile, and compare with saved data

        Pcap dumpPcap = Pcap.openOffline(tempDump.toFile());
        dumpPcap.loop(new PcapHandler() {
            @Override
            protected void newByteBuffer(long timeStamp, int length, ByteBuffer byteBuffer) {
                PacketData packet = allPacketData.remove(0);
                assertEquals(timeStamp, packet.timestamp);
                assertEquals(length, packet.length);
                byteBuffer.rewind();
                assertEquals(byteBuffer, packet.bytes);
            }
        });

        assertEquals(0, allPacketData.size());
    }
}
