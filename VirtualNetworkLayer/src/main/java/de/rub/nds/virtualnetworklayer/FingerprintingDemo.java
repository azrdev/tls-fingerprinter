package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.File;
import java.io.IOException;

public class FingerprintingDemo {
    private static String path = FingerprintingDemo.class.getResource("").getPath();

    public static void main(String[] args) throws IOException {

        ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));

        PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80);

        System.out.println("Fingerprints");
        System.out.println("Direction Labels");
        System.out.println("Request   " + connection.getLabels(Packet.Direction.Request));
        System.out.println("Response  " + connection.getLabels(Packet.Direction.Response));
        System.out.println();

        connection.close();
    }

}
