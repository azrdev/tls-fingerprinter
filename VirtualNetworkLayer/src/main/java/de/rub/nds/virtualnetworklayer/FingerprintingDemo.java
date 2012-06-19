package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.io.File;
import java.io.IOException;

public class FingerprintingDemo {
    private static String path = FingerprintingDemo.class.getResource("").getPath();

    public static void main(String[] args) {
        try {
            ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));

            PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80);
            System.out.println("Fingerprints");
            System.out.println("Direction Labels");
            System.out.println("Request   " + connection.getLabels(Packet.Direction.Request));
            System.out.println("Response  " + connection.getLabels(Packet.Direction.Response));
            System.out.println();

            String request = "GET / HTTP/1.0 \n\n";
            connection.write(request.getBytes());

            connection.read(1000);
            PcapPacket packet = connection.read(1000);
            TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);

            String response = new String(tcpHeader.getPayload());
            System.out.println("Tcp Payload");
            System.out.println(response);

            connection.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
