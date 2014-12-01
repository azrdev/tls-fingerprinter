package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import org.apache.log4j.Logger;

import java.util.List;

public class LoggingFingerprintReporter implements FingerprintReporter {
    private static Logger logger = Logger.getLogger(LoggingFingerprintReporter.class);

    public LoggingFingerprintReporter() {
        logger.info("Logging fingerprints");
    }

	@Override
	public void reportChange(SessionIdentifier sessionIdentifier,
			TLSFingerprint fingerprint,
			List<TLSFingerprint> previousFingerprints) {
		logger.warn("Change detected for " + sessionIdentifier + "\n" + fingerprint);
        for (int i = 0, ps = previousFingerprints.size(); i < ps; i++) {
            TLSFingerprint previous = previousFingerprints.get(i);
            logger.info(fingerprint.difference(previous,
                    String.format("previous #%d", i+1)));
        }
	}

	@Override
	public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
		logger.info(String.format("Saw a Fingerprint again: %s\n%s",
                sessionIdentifier.toString(),
                fingerprint.toString()));
	}

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
		logger.info(String.format("Saw a new Fingerprint: %s\n%s",
                sessionIdentifier.toString(),
                fingerprint.toString()));
    }

    @Override
    public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
        logger.info(String.format("Saw an artificial fingerprint: %s\n%s",
                sessionIdentifier.toString(),
                fingerprint.toString()));
    }
}
