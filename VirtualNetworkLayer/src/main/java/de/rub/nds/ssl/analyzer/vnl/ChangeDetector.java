package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChangeDetector {

	private Map<SessionIdentifier, List<TLSFingerprint>> fingerprints = new HashMap<>();
	private ChangeReporter changeReporter;
	private int changes;
	
	public ChangeDetector(ChangeReporter changeReporter) {
		this.changeReporter = changeReporter;
		this.changes = 0;
	}
	
	public void reportConnection(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
		if (fingerprints.containsKey(sessionIdentifier)) {
			List<TLSFingerprint> previousFingerprints = fingerprints.get(sessionIdentifier);

			if(previousFingerprints.contains(tlsFingerprint)) {
				// We have seen this!
				reportFingerprintUpdate(sessionIdentifier, tlsFingerprint);
				return;
			}
			// A new different fingerprint for this ClientFingerprint
			reportFingerprintChange(sessionIdentifier, tlsFingerprint, previousFingerprints);
			previousFingerprints.add(tlsFingerprint);
		} else {
			// the ClientHelloFingerprint is not yet in fingerprints, add it
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
        changeReporter.reportNew(sessionIdentifier, tlsFingerprint);
    }

	/**
     * sessionIdentifier + tlsFingerprint have already been seen in this combination
	 */
	private void reportFingerprintUpdate(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
		changeReporter.reportUpdate(sessionIdentifier, tlsFingerprint);
	}

	/**
     * we know a different tlsFingerprint for this sessionIdentifier ! Might be MITM!
     */
	private void reportFingerprintChange(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint,
            List<TLSFingerprint> previousFingerprints) {
		changeReporter.reportChange(sessionIdentifier,
                tlsFingerprint,
                previousFingerprints);
		changes++; //TODO: detailed statistics, here or (completely) elsewhere (in reporter?)
	}
	
	public String toString() {
		return String.format("ChangeDetector: saw %d fingerprinted connections, "
                        + "and %d fingerprint changes.",
                        fingerprints.size(), this.changes);
    }
}
