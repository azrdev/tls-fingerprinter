package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.io.IOException;

public class TraceDemo {

    public static void main(String[] args) throws InterruptedException, IOException {

        PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80);

        try {
            String request = "GET / HTTP/1.0 \n\n";
            connection.write(request.getBytes());

            while (connection.available() < 3) {
                Thread.sleep(100);
            }

            for (PcapPacket packet : connection.getTrace()) {
                System.out.println(packet.getHeaders());

                TcpHeader tcpHeader = packet.getHeader(TcpHeader.Id);
                String response = new String(tcpHeader.getPayload());
                System.out.println(response);
            }

            connection.close();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            connection.close();
        }

    }
}
