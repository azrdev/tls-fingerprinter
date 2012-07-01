package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.link.wlan.IEEE802_11Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.io.IOException;

/**
 * This class demonstrates radio frequency monitoring.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class RFMonDemo {

    public static void main(String[] args) throws IOException, InterruptedException {
        //open pcap on local rfmon
        Pcap pcap = Pcap.openRadioFrequencyMonitor();

        pcap.loopAsynchronous(new PacketHandler() {
            @Override
            public void newPacket(PcapPacket packet) {
                IEEE802_11Header header = packet.getHeader(Headers.IEEE802_11);
                System.out.println(header.toFormattedString());
            }
        });
    }

}
