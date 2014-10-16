package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.*;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.SavefileFingerprintReporter;
import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.pcap.PcapDumper;
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
    private static Logger logger = Logger.getLogger(SslReportingConnectionHandler.class);

	static {
		registerP0fFile(P0fFile.Embedded);
	}

    private static final String appDataDir =
            System.getProperty("user.home") + File.separator
                    + ".ssl-reporter" + File.separator;

    private final Path fingerprintsNewDb = Paths.get(appDataDir + "fingerprints_new");
    private final Path fingerprintsChangedDb =
            Paths.get(appDataDir + "fingerprints_changed");

    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;

    private FingerprintListener fingerprintListener = new FingerprintListener();

    private Set<SocketSession> reportedSessions = new HashSet<>();

    private PcapConnection currentConnection = null;

    public SslReportingConnectionHandler() {
        for(Path fpDb : Arrays.asList(fingerprintsNewDb, fingerprintsChangedDb)) {
            try {
                fingerprintListener.loadFingerprintSaveFile(fpDb, false);
            } catch (IOException e) {
                logger.warn("Could not load fingerprint save file: " + e);
            }
            printStats();
        }

        //configure here:
        setFingerprintReporting(true, fingerprintsNewDb, fingerprintsChangedDb, true, true);
    }

    /**
     * Enable/Disable fingerprint reporting modules
     * @param log Enable {@link LoggingFingerprintReporter}
     * @param saveToFileNew Enable serialization of new fingerprints to that file.
     * @param saveToFileChanged Enable serialization of changed fingerprints to that file.
     * @param writeCaptureOnNewFingerprint Write pcap file of every handshake with a
     *                                     new fingerprint
     * @param writeCaptureOnChangedFingerprint Write pcap file of every handshake with a
     *                                     changed fingerprint
     */
    public void setFingerprintReporting(boolean log,
                                        Path saveToFileNew,
                                        Path saveToFileChanged,
                                        final boolean writeCaptureOnNewFingerprint,
                                        final boolean writeCaptureOnChangedFingerprint) {
        fingerprintListener.clearFingerprintReporters();

        if(log)
            fingerprintListener.addFingerprintReporter(new LoggingFingerprintReporter());

        if(saveToFileNew != null || saveToFileChanged != null) {
            try {
                fingerprintListener.addFingerprintReporter(
                        new SavefileFingerprintReporter(saveToFileNew, saveToFileChanged));
            } catch (IOException e) {
                logger.info("Could not open fingerprint save file: " + e);
            }
        }

        if(writeCaptureOnNewFingerprint || writeCaptureOnChangedFingerprint) {
            fingerprintListener.addFingerprintReporter(new FingerprintReporter() {
                @Override
                public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint, List<TLSFingerprint> previousFingerprints) {
                    if(writeCaptureOnChangedFingerprint)
                        writeCapture("changed");
                }

                @Override
                public void reportUpdate(SessionIdentifier s, TLSFingerprint t) {}

                @Override
                public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
                    if(writeCaptureOnNewFingerprint)
                        writeCapture("new");
                }
            });
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
        currentConnection = connection;
        try {

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
        } finally {
            currentConnection = null;
        }
    }

	public void handleUpdate(final PcapConnection connection) {
        //TODO: on every packet (Ethernet frame) we do this again: parse the whole-so-far handshake
		// Did we handle this already?
		SocketSession session = connection.getSession();
		if (!reportedSessions.contains(session)) {
            connection.setKeepRawPackets(true);

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

    private void writeCapture(String nameSuffix) {
        if(currentConnection == null) {
            logger.warn("no current connection");
            return;
        }
        final String name = new Date() + "_" +
                currentConnection.getSession() + "_" +
                nameSuffix + ".pcap";
        PcapDumper pcapDumper = Pcap.getInstance(new byte[]{}).openDump(new File(name));
        for(RawPacket rawPacket : currentConnection.getRawPackets()) {
            pcapDumper.dump(rawPacket.header, rawPacket.bytes);
        }

        currentConnection.setKeepRawPackets(false);
    }
}
