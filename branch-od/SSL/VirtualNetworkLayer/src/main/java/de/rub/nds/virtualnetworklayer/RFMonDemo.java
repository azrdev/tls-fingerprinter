package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.io.IOException;
import java.util.HashMap;

/**
 * This class demonstrates radio frequency monitoring.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class RFMonDemo {

    private static HashMap<String, String> bssids = new HashMap<String, String>();

    public static void main(String[] args) throws IOException, InterruptedException {
        //open pcap on local rfmon
        Pcap pcap = Pcap.openRadioFrequencyMonitor();

        pcap.loopAsynchronous(new PacketHandler(false) {
            @Override
            public void newPacket(PcapPacket packet) {
                if (packet.hasHeader(Headers.IEEE802_11)) {
                    System.out.println(packet.toFormattedString());
                }
            }
        });
    }

}
