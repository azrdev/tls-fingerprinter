package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.application.HttpHeader;

import java.io.IOException;


/**
 * This class demonstrates iterating over a connection's packet trace.
 * </p>
 * exemplary output:
 * <pre>
 * 1340706705566 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706721170 Response [130.83.58.211, 80 | 192.168.6.30, 51232] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706721235 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340705971430 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader, application.HttpHeader]
 * Http Headers {}
 * 1340705985839 Response [130.83.58.211, 80 | 192.168.6.30, 51232] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340705996999 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706005473 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706005840 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706016565 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706016586 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706017069 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706026183 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706027141 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706027646 Request [192.168.6.30, 51232 | 130.83.58.211, 80] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader]
 * 1340706028096 Extended Response [130.83.58.211, 80 | 192.168.6.30, 51232] [link.ethernet.EthernetHeader, internet.Ip4Header, transport.TcpHeader, application.HttpHeader]
 * Http Headers {Content-Language=de, Vary=Accept-Encoding, Date=Tue, 26 Jun 2012 10:17:59 GMT, Set-Cookie=JSESSIONID=A435C8FAC5CECAB9439AE76732BF7D15; Path=/, Content-Type=text/html;charset=UTF-8, Connection=close, Server=Apache/2}
 * </pre>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class TraceDemo {
    private static String request = "GET / HTTP/1.0 \r\n\r\n";

    public static void main(String[] args) throws InterruptedException, IOException {
        PcapConnection connection = PcapConnection.create("www.tu-darmstadt.de", 80);

        try {
            connection.write(request.getBytes());

            //wait until http response reassembly is complete
            synchronized (connection) {
                while (connection.available() < 8 || connection.getTrace().hasIncompleteSequences()) {
                    connection.wait();
                }
            }

            //default iterator uses reassembled sequence order, use connection.getTrace().getArrivalOrder() elsewise
            for (PcapPacket packet : connection.getTrace()) {
                System.out.println(packet + " " + packet.getHeaders());

                //static id lookup
                if (packet.hasHeader(HttpHeader.Id)) {
                    //for convenience: typed lookup
                    HttpHeader httpHeader = packet.getHeader(Headers.Http);
                    System.out.println("Http Headers " + httpHeader.getHeaders());
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            connection.close();
        }

    }
}
