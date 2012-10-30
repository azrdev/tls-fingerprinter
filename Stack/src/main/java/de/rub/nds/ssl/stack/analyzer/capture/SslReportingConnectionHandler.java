package de.rub.nds.ssl.stack.analyzer.capture;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import java.util.ArrayList;
import java.util.List;

/**
 * A connection handler, that tries to find HTTPS connections and reports the
 * current state, whenever a new TLS record layer frame is completed.
 *
 * @author Erik Tews
 *
 */
public final class SslReportingConnectionHandler extends ConnectionHandler {

    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;

    /**
     * Check if a certain connection has source or destination port 443.
     *
     * @param connection
     * @return
     */
    private static boolean isSsl(final PcapConnection connection) {
        return ((connection.getSession().getDestinationPort() == SSL_PORT)
                || (connection.getSession().getSourcePort() == SSL_PORT));
    }

    @Override
    public void newConnection(final Event event,
            final PcapConnection connection) {
        if (event == Event.New && isSsl(connection)) {
            System.out.println("new connection");
            // There is a new SSL connection
            handleUpdate(connection);
        } else if (event == Event.Update && isSsl(connection)) {
            // A new frame has arrived
            handleUpdate(connection);
        }
//        else {
        // System.out.println("nothing of intrested");
//        }
    }

    private static List<MessageContainer> decodeTrace(final PcapTrace trace) {
        List<MessageContainer> frameList = new ArrayList<MessageContainer>();

        // Now, iterate over all packets and find TLS record layer frames
        for (PcapPacket packet : trace) {
            System.out.println(packet + " " + packet.getHeaders());
            System.out.println("direction " + packet.getDirection());
            for (Header header : packet.getHeaders()) {
                if (header instanceof TlsHeader) {
                    // Get the raw bytes of the frame, including the header
                    byte[] content = header.getHeaderAndPayload();

                    // Decode these bytes
                    ARecordFrame[] frames = ACaptureConverter
                            .decodeRecordFrames(content);

                    // Convert all Frames to MessageContainer and add them to
                    // the list
                    for (int i = 0; i < frames.length; i++) {
                        frameList.add(new MessageContainer(frames[i], packet));
                        if (frames[i] instanceof ChangeCipherSpec) {
                            /*
                             * From now on, there is encryption and we cannot 
                             * decode it anymore.
                             */
                            return frameList;
                        }
                    }
                }
            }
        }
        return frameList;
    }

    public void handleUpdate(final PcapConnection connection) {

        // Get a trace of all previous packets
        PcapTrace trace = connection.getTrace();

        // Prepare a list for all MessageContainer
        List<MessageContainer> frameList = decodeTrace(trace);

        if (frameList.size() > 0) {
            // Now, print a full status report for that connection

            System.out.println("Received an Update for Connection "
                    + connection);
            for (MessageContainer aRecordFrame : frameList) {
                System.out.println(aRecordFrame.getCurrentRecord());
            }
            System.out.println("end of trace");
        }
    }
}
