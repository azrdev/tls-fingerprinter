package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.IOException;

/**
 * This class demonstrates the fingerprinting capabilities.
 * </p>
 * exemplary output:
 * <pre>
 * Fingerprints
 * Direction Labels
 * Request   [Ethernet or modem, s:unix:Mac OS X:10.x]
 * Response  [generic tunnel or VPN, s:unix:Linux:2.6.x]
 * </pre>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class FingerprintingDemo {
    public static void main(String[] args) throws IOException {
        //register embedded fingerprints: p0f.fp taken from p0f version 3.05b
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);

        PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80);

        //if active live device cannot be discovered, set manually
        //Pcap.setLiveDevice(Device.Any);
        //or use
        //PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80, "192.168.6.20");

        System.out.println("Fingerprints");
        System.out.println("Direction Labels");
        System.out.println("Request   " + connection.getLabels(Packet.Direction.Request));
        System.out.println("Response  " + connection.getLabels(Packet.Direction.Response));
        System.out.println();

        connection.close();
    }

}
