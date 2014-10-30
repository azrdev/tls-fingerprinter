package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import org.apache.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class FingerprintListener {
    private Logger logger = Logger.getLogger(getClass());

    private Map<SessionIdentifier, List<TLSFingerprint>> fingerprints = new HashMap<>();
    private Collection<FingerprintReporter> reporters = new LinkedList<>();

    //statistics / counts
    private int fingerprintsNew;
    private int fingerprintsUpdates;
    private int fingerprintsChanges;

    public FingerprintListener() {
        this.fingerprintsChanges = 0;
    }

    public boolean addFingerprintReporter(FingerprintReporter fr) {
        return reporters.add(fr);
    }

    public boolean removeFingerprintReporter(FingerprintReporter fr) {
        return reporters.remove(fr);
    }

    public void clearFingerprintReporters() {
        reporters.clear();
    }

    public void reportConnection(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
        if (fingerprints.containsKey(sessionIdentifier)) {
            List<TLSFingerprint> previousFingerprints = fingerprints.get(sessionIdentifier);

            if(previousFingerprints.contains(tlsFingerprint)) {
                // We have seen this!
                reportFingerprintUpdate(sessionIdentifier, tlsFingerprint);
                //TODO: store seen count
                return;
            }
            // A new different fingerprint for this ClientFingerprint
            reportFingerprintChange(sessionIdentifier, tlsFingerprint, previousFingerprints);
            previousFingerprints.add(tlsFingerprint);
        } else {
            // the ClientFingerprint is not yet in fingerprints, add it
            List<TLSFingerprint> fingerprintList = new ArrayList<>(1);
            fingerprintList.add(tlsFingerprint);
            reportFingerprintNew(sessionIdentifier, tlsFingerprint);
            fingerprints.put(sessionIdentifier, fingerprintList);
        }
    }

    /**
     * first occurrence of sessionIdentifier, with accompanying tlsFingerprint
     */
    private void reportFingerprintNew(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
        for(FingerprintReporter fingerprintReporter : reporters) {
            fingerprintReporter.reportNew(sessionIdentifier, tlsFingerprint);
        }
        ++fingerprintsNew;
    }

    /**
     * sessionIdentifier + tlsFingerprint have already been seen in this combination
     */
    private void reportFingerprintUpdate(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
        for(FingerprintReporter fingerprintReporter : reporters) {
            fingerprintReporter.reportUpdate(sessionIdentifier, tlsFingerprint);
        }
        ++fingerprintsUpdates;
    }

    /**
     * we know a different tlsFingerprint for this sessionIdentifier ! Might be MITM!
     */
    private void reportFingerprintChange(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint,
            List<TLSFingerprint> previousFingerprints) {
        for(FingerprintReporter fingerprintReporter : reporters) {
            fingerprintReporter.reportChange(sessionIdentifier,
                    tlsFingerprint,
                    previousFingerprints);
        }
        ++fingerprintsChanges;
    }

    public String toString() {
        return String.format("Endpoints: %d; Fingerprints: New %d, Updates %d, Changes %d",
                fingerprints.size(),
                fingerprintsNew,
                fingerprintsUpdates,
                fingerprintsChanges);
        //TODO: detailed statistics, here or (completely) elsewhere (in reporter?)
    }

    /**
     * read all fingerprints in saveFile to the internal store.
     * <p>
     * <b>NOTE</b>: currently this overrides everything already in the internal store
     * @param overrideExisting Clear the currently known fingerprints before loading
     * @throws IOException
     */
    public void loadFingerprintSaveFile(Path saveFile, boolean overrideExisting)
            throws IOException {
        logger.info("loading from " + saveFile);

        BufferedReader br = Files.newBufferedReader(saveFile, Charset.forName("UTF8"));
        Map<SessionIdentifier, List<TLSFingerprint>> fingerprints =
                Serializer.deserialize(br);

        if(overrideExisting) {
            logger.info("override stored fingerprints");
            this.fingerprints.putAll(fingerprints);
        } else {
            for(Map.Entry<SessionIdentifier, List<TLSFingerprint>> e :
                    fingerprints.entrySet()) {
                if (!this.fingerprints.containsKey(e.getKey())) {
                    this.fingerprints.put(e.getKey(), e.getValue());
                } else {
                    List<TLSFingerprint> fps = this.fingerprints.get(e.getKey());
                    // check each TLSFingerprint on its own, to report & avoid duplicates
                    for(TLSFingerprint fp : e.getValue()) {
                        if(fps.contains(fp)) {
                            logger.warn("fingerprint in file already known: " +
                                    e.getKey());
                            logger.trace("fingerprint: " + fp);
                        } else {
                            fps.add(fp);
                        }
                    }
                }
            }
        }
    }
}
