package de.rub.nds.ssl.analyzer.vnl;

import java.util.HashSet;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.*;
import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;
import org.apache.log4j.Logger;

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

    private Logger logger = Logger.getLogger(getClass());

    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;
    
    private FingerprintListener fingerprintListener =
            new FingerprintListener(new PrintingFingerprintReporter());
    
    public void printStats() {
    	logger.info(fingerprintListener.toString());
    }

    /**
     * Check if a certain connection has source or destination port 443.
     */
    private static boolean isSsl(final PcapConnection connection) {
        return ((connection.getSession().getDestinationPort() == SSL_PORT)
                || (connection.getSession().getSourcePort() == SSL_PORT));
    }
    
    private HashSet<SocketSession> reportedSessions = new HashSet<>();

    @Override
    public void newConnection(final Event event, final PcapConnection connection) {

        if (isSsl(connection)) {
            if (event == Event.New) {
                // logger.info("new connection");
                // There is a new SSL connection
                handleUpdate(connection);
            } else if (event == Event.Update) {
                // A new frame has arrived
                handleUpdate(connection);
            }
        }
    }

	public void handleUpdate(final PcapConnection connection) {

		// Did we handle this already?
		SocketSession session = connection.getSession();
		if (!reportedSessions.contains(session)) {

			Connection c;
			try {
				c = new Connection(connection);
			} catch (Throwable e) {
				logger.warn("Error decoding connection: " + e, e);
				return;
			}
			if (c.isCompleted()) {
				reportedSessions.add(session);

                SessionIdentifier sessionIdentifier = c.getSessionIdentifier();
                TLSFingerprint tlsFingerprint = new TLSFingerprint(c);

                fingerprintListener.reportConnection(sessionIdentifier, tlsFingerprint);

				//c.printReport();
			}

		}
	}
}
