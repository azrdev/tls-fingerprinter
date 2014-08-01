package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChangeDetector {

	private Map<Fingerprint.Signature,
			    List<ServerFingerprint>> fingerprints = new HashMap<>();
	private ChangeReporter changeReporter;
	private int changes;
	
	public ChangeDetector(ChangeReporter changeReporter) {
		this.changeReporter = changeReporter;
		this.changes = 0;
	}
	
	public void reportConnection(Fingerprint.Signature cs, ServerFingerprint sf) {
		if (fingerprints.containsKey(cs)) {
			List<ServerFingerprint> previousFingerprints = fingerprints.get(cs);

			if(previousFingerprints.contains(sf)) {
				// We have seen this!
				reportFingerprintUpdate(cs, sf);
				return;
			}
			// A new different fingerprint for this ClientFingerprint
			reportFingerprintChange(cs, sf, previousFingerprints);
			previousFingerprints.add(sf);
		} else {
			// the ClientHelloFingerprint is not yet in fingerprints, add it
			List<ServerFingerprint> sfs = new ArrayList<>(1);
			sfs.add(sf);
			reportFingerprintUpdate(cs, sf);
			fingerprints.put(cs, sfs);
		}
	}

	/**
	 * either we see this chf for the first time, or we have already seen both together
     *
     * TODO: distinguish new and updated fingerprint
	 */
	private void reportFingerprintUpdate(Fingerprint.Signature cs,
	                                     ServerFingerprint sf) {
		changeReporter.reportUpdate(cs, sf);
	}

	/**
	 * this chf + sf combination is new to us
     * @param cs
     * @param previousFingerprints
     */
	private void reportFingerprintChange(Fingerprint.Signature cs,
	                                  ServerFingerprint sf,
	                                  List<ServerFingerprint> previousFingerprints) {
		changeReporter.reportChange(cs, sf, previousFingerprints);
		changes++;
	}
	
	public String toString() {
		return String.format("ChangeDetector: saw %d ClientFingerprints, "
				+ "and %d ServerFingerprint changes.",
                fingerprints.size(), this.changes);
    }
}
