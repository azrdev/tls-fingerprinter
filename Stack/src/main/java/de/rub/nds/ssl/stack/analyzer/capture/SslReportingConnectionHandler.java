package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.HashSet;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;

/**
 * A connection handler, that tries to find HTTPS connections and reports the
 * current state, whenever a new TLS record layer frame is completed.
 *
 * @author Erik Tews
 *
 */
public final class SslReportingConnectionHandler extends ConnectionHandler {

	static {
		registerP0fFile(P0fFile.Embedded);
	}

    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;
    
    private ChangeDetector cd = new ChangeDetector(new PrintingChangeReporter());

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
    
    private HashSet<SocketSession> reportedSessions = new HashSet<SocketSession>();

    @Override
    public void newConnection(final Event event,
            final PcapConnection connection) {
        if (event == Event.New && isSsl(connection)) {
            // System.out.println("new connection");
            // There is a new SSL connection
            handleUpdate(connection);
        } else if (event == Event.Update && isSsl(connection)) {
            // A new frame has arrived
            handleUpdate(connection);
        }
    }

	public void handleUpdate(final PcapConnection connection) {

		// Did we handle this already?
		SocketSession session = connection.getSession();
		if (!reportedSessions.contains(session)) {

			Connection c = null;
			try {
				c = new Connection(connection);
			} catch (Throwable e) {
				// Ignore that for now
				return;
			}
			if (c.isCompleted()) {
				reportedSessions.add(session);
				cd.reportConnection(c.getClientHelloFingerprint(), c.getServerFingerprint());
				// c.printReport();
				/*
				System.out.println("Found a connection to: " + c.getServerHostName());
				System.out.println("Label was " + c.getNetworkFingerprint());
				System.out.println("Client Hello was: " + c.getClientHelloFingerprint());
				System.out.println("Server Hello was: " + c.getServerHelloFingerprint());
				*/
			}

		}
	}
}
