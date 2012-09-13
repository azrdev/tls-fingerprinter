package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.FragmentSequence;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.connection.pcap.ReassembledPacket;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.util.List;

/**
 * This class demonstrates tcp reassembly.
 * </p>
 * exemplary output:
 * <pre>
 * [192.168.6.30, 53452 | 192.168.6.31, 6000]
 * [67.222.104.211, 8000 | 192.168.6.30, 49999]
 * [192.168.6.30, 51439 | 173.194.35.159, 443]
 * [192.168.6.30, 6002 | 192.168.6.31, 6001]
 * ReassembledPackets
 * 1340708792420 Cropped Response [173.194.35.159, 443 | 192.168.6.30, 51439] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader, application.TlsHeader]
 * Content Type Handshake
 *
 * 1340708792937 Extended Response [173.194.35.159, 443 | 192.168.6.30, 51439] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader, application.TlsHeader, application.TlsHeader]
 * Content Type Handshake
 * Content Type Handshake
 * </pre>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class ReassemblingDemo {
    private static String request = "GET / HTTP/1.0 \r\n\r\n";
    private static PcapConnection sslConnection;

    public static void main(String[] args) throws IOException, InterruptedException {
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);

        //open pcap on local live device
        Pcap pcap = Pcap.openLive();
        

        //simple connection handler, saves first connection on port 443 and prints sessions
        pcap.loopAsynchronous(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                if (event == Event.New && connection.getSession().getDestinationPort() == 443) {
                    sslConnection = connection;
                }

                System.out.println(connection);
            }
        });

        SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) sslFactory.createSocket("www.google.de", 443);
        socket.getOutputStream().write(request.getBytes());

        //wait for certificate (1st fragment sequence)
        PcapTrace trace = sslConnection.getTrace();
        List<FragmentSequence> sequences = trace.getFragmentSequences();
        while (sequences.size() == 0 || !sequences.get(0).isComplete()) {
            synchronized (sslConnection) {
                sslConnection.wait();
            }
        }

        System.out.println("ReassembledPackets");
        for (PcapPacket packet : sslConnection.getTrace()) {
            if (packet instanceof ReassembledPacket) {
                System.out.println(packet + " " + packet.getHeaders());

                for (Header header : packet.getHeaders()) {
                    if (header instanceof TlsHeader) {
                        TlsHeader tlsHeader = (TlsHeader) header;
                        System.out.println("Content Type " + tlsHeader.getContentType());
                    }
                }

                System.out.println();
            }
        }

        pcap.close();
    }

}
