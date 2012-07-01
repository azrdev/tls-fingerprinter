package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.io.IOException;

/**
 * This class demonstrates connection reporting.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see #verbose
 */
public class ReportingDemo {
    //set true for printing formatted packets
    private static boolean verbose = true;

    public static void main(String[] args) throws IOException, InterruptedException {
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);
        Pcap pcap = Pcap.openLive();

        pcap.loopAsynchronous(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                if (event == Event.Update) {
                    System.out.println(connection);

                    if (connection.getLabel(Packet.Direction.Request, Fingerprints.Tcp) != null) {
                        System.out.println(connection.getLabels(Packet.Direction.Response));
                    }

                    if (verbose) {
                        PcapPacket packet = connection.getTrace().getLast();
                        if (packet != null) {
                            System.out.println(packet.toFormattedString());
                        }
                    }
                }

            }
        });
    }
}
