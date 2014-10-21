package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.*;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.SavefileFingerprintReporter;
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
 * @author jBiegert azrdev@qrdn.de
 *
 */
public final class SslReportingConnectionHandler extends ConnectionHandler {

	static {
		registerP0fFile(P0fFile.Embedded);
	}

    private static final String appDataDir =
            System.getProperty("user.home") + File.separator
                    + ".ssl-reporter" + File.separator;
    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;

    private Logger logger = Logger.getLogger(getClass());

    private FingerprintListener fingerprintListener;

    private Set<SocketSession> reportedSessions = new HashSet<>();

    public SslReportingConnectionHandler() {
        Path fingerprintDbFile = Paths.get(appDataDir + "fingerprints");
        fingerprintListener = new FingerprintListener();
        try {
            fingerprintListener.loadFingerprintSaveFile(fingerprintDbFile, false);
        } catch (IOException e) {
            logger.warn("Could not load fingerprint save file " + fingerprintDbFile +
                " - " + e);
        }
        printStats();
        setFingerprintReporting(true, fingerprintDbFile);
    }

    public void setFingerprintReporting(boolean log, Path saveToFile) {
        fingerprintListener.clearFingerprintReporters();

        if(log)
            fingerprintListener.addFingerprintReporter(new LoggingFingerprintReporter());

        if(saveToFile != null) {
            try {
                fingerprintListener.addFingerprintReporter(
                        new SavefileFingerprintReporter(saveToFile));
            } catch (IOException e) {
                logger.info("Could not open fingerprint save file: " + e);
            }
        }
    }
    
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
        //TODO: on every packet (Ethernet frame) we do this again: parse the whole-so-far handshake
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
                if(sessionIdentifier.isValid()) {
                    TLSFingerprint tlsFingerprint = new TLSFingerprint(c);
                    fingerprintListener.reportConnection(sessionIdentifier,
                            tlsFingerprint);
                }

				//c.printReport();
			}

		}
	}
}
