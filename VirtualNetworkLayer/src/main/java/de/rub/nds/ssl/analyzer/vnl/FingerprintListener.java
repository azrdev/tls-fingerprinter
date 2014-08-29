package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.*;

public class FingerprintListener {

	private Map<SessionIdentifier, List<TLSFingerprint>> fingerprints = new HashMap<>();
	private Collection<FingerprintReporter> reporters = new LinkedList<>();
	private int changes;
	
	public FingerprintListener() {
		this.changes = 0;
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
        for(FingerprintReporter fingerprintReporter : reporters) {
            fingerprintReporter.reportNew(sessionIdentifier, tlsFingerprint);
        }
    }

	/**
     * sessionIdentifier + tlsFingerprint have already been seen in this combination
	 */
	private void reportFingerprintUpdate(SessionIdentifier sessionIdentifier,
            TLSFingerprint tlsFingerprint) {
        for(FingerprintReporter fingerprintReporter : reporters) {
            fingerprintReporter.reportUpdate(sessionIdentifier, tlsFingerprint);
        }
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
		changes++; //TODO: detailed statistics, here or (completely) elsewhere (in reporter?)
	}
	
	public String toString() {
		return String.format("saw %d fingerprinted connections, "
                        + "and %d fingerprint changes.",
                        fingerprints.size(), this.changes);
    }
}
