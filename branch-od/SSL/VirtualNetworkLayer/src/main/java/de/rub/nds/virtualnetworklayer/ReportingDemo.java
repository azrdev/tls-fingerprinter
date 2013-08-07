package de.rub.nds.virtualnetworklayer;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;

import java.io.IOException;
import java.util.EnumSet;

/**
 * This class demonstrates connection reporting.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see #verbose
 */
public class ReportingDemo {
    //set true for printing formatted packets
    private static boolean verbose = true;
    private static boolean promiscuous = false;

    public static void main(String[] args) throws IOException, InterruptedException {
        ConnectionHandler.registerP0fFile(P0fFile.Embedded);

        Pcap pcap = null;
        if (promiscuous) {
            pcap = Pcap.openLive(Pcap.getLiveDevice(), EnumSet.of(Pcap.OpenFlag.Promiscuous));
        } else {
            pcap = Pcap.openLive();
        }

        pcap.loopAsynchronous(new ConnectionHandler() {
            @Override
            public void newConnection(Event event, PcapConnection connection) {
                if (event == Event.Update) {

                    if (connection.getLabel(Packet.Direction.Response, Fingerprints.Tcp) != null) {
                        System.out.println(connection.getLabels(Packet.Direction.Response));
                    }

                    if (verbose) {
                        PcapPacket packet = connection.getTrace().getLast();
                        if (packet != null) {
                            System.out.println(packet.toFormattedString());
                        }
                    } else {
                        System.out.println(connection);
                    }
                }

            }
        });
    }
}
