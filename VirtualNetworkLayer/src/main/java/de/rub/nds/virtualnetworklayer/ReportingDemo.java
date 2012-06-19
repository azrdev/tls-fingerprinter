package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.io.File;
import java.io.IOException;

public class ReportingDemo {
    private static String path = FingerprintingDemo.class.getResource("").getPath();

    public static void main(String[] args) {
        try {
            ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));

            Pcap pcap = Pcap.openLive();
            pcap.loop(new ConnectionHandler() {
                @Override
                public void newConnection(PcapConnection connection) {
                    System.out.println(connection.getSession());
                }
            }, true);

            PcapConnection connection = PcapConnection.create("www.google.de", 443);

            String request = "GET / HTTP/1.0 \n\n";
            connection.write(request.getBytes());

            PcapPacket packet = connection.read(1000);
            System.out.println(packet.getHeaders());

            connection.close();
            pcap.finalize();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
