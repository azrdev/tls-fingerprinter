package de.rub.nds.ssl.analyzer.vnl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter.FingerprintReporterAdapter;
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

    private static final String appDataDir =
            System.getProperty("user.home") + File.separator + ".ssl-reporter" + File.separator;

    private final Path fingerprintsNewDb = Paths.get(appDataDir + "fingerprints_new");
    private final Path fingerprintsChangedDb = Paths.get(appDataDir + "fingerprints_changed");
    private final Path fingerprintsGuessedDb = Paths.get(appDataDir + "fingerprints_guessed");

    private final String captureDir = appDataDir + File.separator + "captures" + File.separator;

    private static final String statisticsFile = appDataDir + "statistics.ser";

    private FingerprintListener fingerprintListener = new FingerprintListener();
    private FingerprintStatistics statistics = new FingerprintStatistics();

    private Set<SocketSession> reportedSessions = new HashSet<>();

    private PcapConnection currentConnection = null;
    private Pcap pcap = null;

    public SslReportingConnectionHandler() {
        this(true);
    }

    /**
     * ctor
     * @param deserialize (default: true) Read stored fingerprints & statistics.
     */
    public SslReportingConnectionHandler(boolean deserialize) {
        registerP0fFile(P0fFile.Embedded);

        if(deserialize) {
            try {
                Files.createDirectories(Paths.get(appDataDir));
            } catch (IOException e) {
                logger.warn("Could not mkdir " + appDataDir + " : " + e);
            }

            // de-serialize statistics
            ObjectInputStream os = null;
            try {
                os = new ObjectInputStream(new FileInputStream(statisticsFile));
                statistics = (FingerprintStatistics) os.readObject();
            } catch (IOException | ClassNotFoundException | ClassCastException e) {
                logger.warn("Could not read statistics file: " + e, e);
            } finally {
                try {
                    os.close();
                } catch (IOException | NullPointerException e) { /**/ }
            }
        }
        logger.info("Successfully read statistics file");
        statistics.log(true);

        if(deserialize) {
            // de-serialize fingerprints in  save files
            for (Path fpDb : Arrays.asList(
                    fingerprintsNewDb, fingerprintsChangedDb, fingerprintsGuessedDb)) {
                try {
                    fingerprintListener.loadFingerprintSaveFile(fpDb, false);
                } catch (IOException e) {
                    logger.warn("Could not load fingerprint save file: " + e);
                }
            }
        }
        fingerprintListener.log();
    }

    /**
     * @see #setFingerprintReporting(boolean, Path, Path, Path, boolean, boolean, boolean)
     */
    void setFingerprintReporting(boolean log,
                                        boolean saveFingerprintsToFile,
                                        boolean writeCaptures,
                                        boolean guessResumptionFingerprints) {
        final Path nDb = saveFingerprintsToFile? fingerprintsNewDb : null;
        final Path cDb = saveFingerprintsToFile? fingerprintsChangedDb : null;
        final Path gDb = saveFingerprintsToFile? fingerprintsGuessedDb : null;
        setFingerprintReporting(log, nDb, cDb, gDb, writeCaptures, writeCaptures, guessResumptionFingerprints);
    }

    /**
     * Enable/Disable fingerprint reporting modules
     * @param log Enable {@link LoggingFingerprintReporter}
     * @param saveToFileNew Enable serialization of new fingerprints to that file.
     * @param saveToFileChanged Enable serialization of changed fingerprints to that file.
     * @param saveToFileGuessed Enable serialization of guessed fingerprints to that file.
     * @param writeCaptureOnNewFingerprint Write pcap file of every handshake with a
     *                                     new fingerprint
     * @param writeCaptureOnChangedFingerprint Write pcap file of every handshake with a
     *                                     changed fingerprint
     * @param guessResumptionFingerprints Enable {@link ResumptionFingerprintGuesser}
     */
    void setFingerprintReporting(boolean log,
                                        Path saveToFileNew,
                                        Path saveToFileChanged,
                                        Path saveToFileGuessed,
                                        final boolean writeCaptureOnNewFingerprint,
                                        final boolean writeCaptureOnChangedFingerprint,
                                        boolean guessResumptionFingerprints) {
        //TODO: this also removes all other reporters (e.g. from UI)
        fingerprintListener.clearFingerprintReporters();

        fingerprintListener.addFingerprintReporter(statistics);

        if(log)
            fingerprintListener.addFingerprintReporter(new LoggingFingerprintReporter());

        if(saveToFileNew != null || saveToFileChanged != null) {
            try {
                fingerprintListener.addFingerprintReporter(
                        new SavefileFingerprintReporter(saveToFileNew,
                                saveToFileChanged,
                                saveToFileGuessed));
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

                fingerprintListener.addFingerprintReporter(new FingerprintReporterAdapter() {
                    @Override
                    public void reportChange(SessionIdentifier sessionIdentifier,
                                             TLSFingerprint fingerprint,
                                             Set<TLSFingerprint> previousFingerprints) {
                        if (writeCaptureOnChangedFingerprint)
                            writeCapture("changed");
                    }

                    @Override
                    public void reportNew(SessionIdentifier sessionIdentifier,
                                          TLSFingerprint tlsFingerprint) {
                        if (writeCaptureOnNewFingerprint)
                            writeCapture("new");
                    }
                });
            } catch(IOException e) {
                logger.info("Could not create capture directory " + e);
            }
        }

        if(guessResumptionFingerprints)
            fingerprintListener.addFingerprintReporter(
                    new ResumptionFingerprintGuesser(fingerprintListener));
    }

    public void printStats(boolean verbose) {
        if(verbose)
            fingerprintListener.log();
        statistics.log(verbose);
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

		SocketSession session = connection.getSession();
		if (reportedSessions.contains(session))
            return;

        // keep raw packets for dump capture. if not done yet,
        // we have to keep the current packet, too
        if(! connection.keepRawPackets())
            saveRawPacket(connection);
        connection.setKeepRawPackets(true);

        // parse TLS
        Connection tlsConnection;
        try {
            tlsConnection = new Connection(connection);
        } catch (Throwable e) {
            logger.warn("Error decoding connection: " + e);
            logger.trace("backtrace: ", e);
            return;
        }

        // if handshake is completed, fingerprint
        if (tlsConnection.isCompleted()) {
            reportedSessions.add(session);

            SessionIdentifier sessionIdentifier = tlsConnection.getSessionIdentifier();
            if(sessionIdentifier.isValid()) {
                TLSFingerprint tlsFingerprint = new TLSFingerprint(tlsConnection);
                fingerprintListener.reportConnection(sessionIdentifier, tlsFingerprint);
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
                (new SimpleDateFormat("yyyy-MM-dd HH-mm-ss-SSS ").format(new Date()) +
                currentConnection.getSession() + " " +
                nameSuffix).replaceAll("[^\\w\\s-]", "_") + ".pcap";
        logger.debug("Writing capture to " + name);

        PcapDumper pcapDumper = this.pcap.openDump(new File(name));
        for(RawPacket rawPacket : currentConnection.getRawPackets()) {
            pcapDumper.dump(rawPacket);
        }

        currentConnection.setKeepRawPackets(false, true);
        return true;
    }

    /**
     * Set the {@link Pcap} instance that loops using this handler.
     * <p>
     * <b>This will break when more than one Pcap loops with the same handler</b>
     */
    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }

    public FingerprintListener getFingerprintListener() {
        return fingerprintListener;
    }

    public FingerprintStatistics getFingerprintStatistics() {
        return statistics;
    }

    public void saveStatistics() {
        try {
            ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(statisticsFile));
            os.writeObject(statistics);
        } catch (IOException e) {
            logger.error("Could not write statistics: " + e, e);
            return;
        }
        logger.info("Successfully wrote statistics to " + statisticsFile);
    }
}
