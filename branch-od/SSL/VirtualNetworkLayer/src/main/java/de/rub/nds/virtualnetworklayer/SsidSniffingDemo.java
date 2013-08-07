package de.rub.nds.virtualnetworklayer;


import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PacketHandler;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.link.wlan.IEEE802_11Header;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;

import java.io.IOException;
import java.util.HashMap;

public class SsidSniffingDemo {

    private static HashMap<String, String> bssids = new HashMap<String, String>();

    public static void main(String[] args) throws IOException, InterruptedException {
        Pcap pcap = Pcap.openRadioFrequencyMonitor();

        //deactivate deep package copying for performance reasons
        boolean deepCopy = false;

        pcap.loopAsynchronous(new PacketHandler(deepCopy) {
            @Override
            public void newPacket(PcapPacket packet) {
                if (packet.hasHeader(Headers.IEEE802_11)) {
                    IEEE802_11Header header = packet.getHeader(Headers.IEEE802_11);

                    byte[] bssid = null;
                    if (header.getType() == IEEE802_11Header.Type.Management
                            && (bssid = header.getAddress(IEEE802_11Header.Address.BasicServiceSet)) != null && !header.isCorrupted()) {

                        String formattedBssid = MacFormatter.toString(bssid);
                        String ssid = bssids.get(formattedBssid);

                        if (ssid == null || ssid.equals('\0')) {
                            if (!header.getSsid().isEmpty()) {
                                ssid = header.getSsid();
                                System.out.println(formattedBssid + " " + ssid);

                            } else if (!bssids.containsKey(formattedBssid)) {
                                System.out.println(formattedBssid + " <hidden>");
                            }

                            bssids.put(formattedBssid, ssid);
                        }
                    }

                }
            }
        });
    }
}
