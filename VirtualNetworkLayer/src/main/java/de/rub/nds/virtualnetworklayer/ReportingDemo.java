package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.FragmentSequence;
import de.rub.nds.virtualnetworklayer.connection.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.ReassembledPacket;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.util.List;

public class ReportingDemo {
    private static String path = FingerprintingDemo.class.getResource("").getPath();
    private static PcapConnection pcapConnection;

    public static void main(String[] args) throws IOException, InterruptedException {

        ConnectionHandler.registerP0fFile(new File(path, "p0f.fp"));

        Pcap pcap = Pcap.openLive();
        pcap.loopAsynchronous(new ConnectionHandler() {
            @Override
            public void newConnection(PcapConnection connection) {
                ReportingDemo.pcapConnection = connection;
                System.out.println(connection.getSession());
            }
        });

        SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) sslFactory.createSocket("www.google.de", 443);

        String request = "GET / HTTP/1.0 \n\n";
        socket.getOutputStream().write(request.getBytes());

        List<FragmentSequence> sequences = ReportingDemo.pcapConnection.getTrace().getFragmentSequences();

        while (sequences.size() == 0 || !sequences.get(0).isComplete()) {
            synchronized (ReportingDemo.pcapConnection) {
                ReportingDemo.pcapConnection.wait();
            }
        }

        System.out.println("ReassembledPackets");
        for (PcapPacket packet : ReportingDemo.pcapConnection.getTrace()) {
            if (packet instanceof ReassembledPacket) {
                System.out.println("Headers " + packet.getHeaders());

                for (Header header : packet.getHeaders()) {
                    if (header instanceof TlsHeader) {
                        TlsHeader tlsHeader = (TlsHeader) header;
                        System.out.println("Content Type " + tlsHeader.getContentType());
                    }
                }

                System.out.println();
            }
        }

        pcap.finalize();
    }

}
