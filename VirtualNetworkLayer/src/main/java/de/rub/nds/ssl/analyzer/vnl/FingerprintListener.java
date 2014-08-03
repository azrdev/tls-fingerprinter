package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FingerprintListener {

	private Map<SessionIdentifier, List<TLSFingerprint>> fingerprints = new HashMap<>();
	private FingerprintReporter fingerprintReporter;
	private int changes;
	
	public FingerprintListener(FingerprintReporter fingerprintReporter) {
		this.fingerprintReporter = fingerprintReporter;
		this.changes = 0;
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
        fingerprintReporter.reportNew(sessionIdentifier, tlsFingerprint);
    }

	/**
     * sessionIdentifier + tlsFingerprint have already been seen in this combination
	 */
	private void reportFingerprintUpdate(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
		fingerprintReporter.reportUpdate(sessionIdentifier, tlsFingerprint);
	}

	/**
     * we know a different tlsFingerprint for this sessionIdentifier ! Might be MITM!
     */
	private void reportFingerprintChange(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint,
            List<TLSFingerprint> previousFingerprints) {
		fingerprintReporter.reportChange(sessionIdentifier,
                tlsFingerprint,
                previousFingerprints);
		changes++; //TODO: detailed statistics, here or (completely) elsewhere (in reporter?)
	}
	
	public String toString() {
		return String.format("FingerprintListener: saw %d fingerprinted connections, "
                        + "and %d fingerprint changes.",
                        fingerprints.size(), this.changes);
    }
}
