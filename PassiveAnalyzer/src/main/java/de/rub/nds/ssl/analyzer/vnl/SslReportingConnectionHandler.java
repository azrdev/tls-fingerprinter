package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.*;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.SavefileFingerprintReporter;
import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.p0f.P0fFile;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
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
    private final String captureDir = appDataDir + File.separator +
            "captures" + File.separator;

    /**
     * Default SSL Port.
     */
    private static final int SSL_PORT = 443;

    private FingerprintListener fingerprintListener = new FingerprintListener();

    private Set<SocketSession> reportedSessions = new HashSet<>();

    private PcapConnection currentConnection = null;
    private Pcap pcap = null;

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
            final String what = Joiner.on(',').skipNulls().join(
                    writeCaptureOnNewFingerprint? "new" : null,
                    writeCaptureOnChangedFingerprint? "changed" : null);
            logger.info("Writing captures of " + what + " fingerprints to " + captureDir);

            try {
                Files.createDirectories(Paths.get(captureDir));

                fingerprintListener.addFingerprintReporter(new FingerprintReporter() {
                    @Override
                    public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint, List<TLSFingerprint> previousFingerprints) {
                        if (writeCaptureOnChangedFingerprint)
                            writeCapture("changed");
                    }

                    @Override
                    public void reportUpdate(SessionIdentifier s, TLSFingerprint t) {
                    }

                    @Override
                    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
                        if (writeCaptureOnNewFingerprint)
                            writeCapture("new");
                    }
                });
            } catch(IOException e) {
                logger.info("Could not create capture directory " + e);
            }
        }
    }
    
    public void printStats() {
    	logger.info(fingerprintListener.toString());
    }

    /**
     * Check if connection contains any TLS packets. Relies on protocol recognition in
     * {@link de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader}.
     * @return <code>true</code> if any TLS packets were found. If not,
     * the connection may be in the TCP handshake, and TLS packets will occur later.
     */
    private static boolean isSsl(final PcapConnection connection) {
        PcapTrace trace = connection.getTrace();
        if(trace == null) {
            logger.debug("got connection without trace: " + connection);
            return false;
        }

        Iterator<PcapPacket> packets = trace.getArrivalOrder();
        while(packets.hasNext()) {
            if(packets.next().getHeaders(Headers.Tls).size() > 0)
                return true;
        }
        return false;
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

    /**
     * Takes the currently handled connection and write its stored packet data to a
     * pcap file in {@link #captureDir}.
     * Requires {@link #setPcap(Pcap)} to have set the looping pcap instance.
     *
     * @see PcapConnection#getRawPackets()
     * @see Pcap#openDump(File)
     */
    private boolean writeCapture(String nameSuffix) {
        if(currentConnection == null) {
            logger.warn("no current connection");
            return false;
        }

        final String name = captureDir +
                new SimpleDateFormat("yyyy-MM-dd HH-mm-ss").format(new Date()) + "_" +
                currentConnection.getSession() + "_" +
                nameSuffix + ".pcap";
        logger.debug("Writing capture to " + name);

        PcapDumper pcapDumper = this.pcap.openDump(new File(name));
        for(RawPacket rawPacket : currentConnection.getRawPackets()) {
            pcapDumper.dump(rawPacket.getHeaderNative(), rawPacket.getBytesNative());
        }

        currentConnection.setKeepRawPackets(false);
        return true;
    }

    /**
     * Set the {@link Pcap} instance that loops using this handler.
     * <p>
     * <b>This will break when more than one Pcap loops with the same handler</b>
     * @param pcap
     */
    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }
}
