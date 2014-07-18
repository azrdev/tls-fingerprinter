package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChangeDetector {

	private Map<ClientHelloFingerprint,
			    List<ServerFingerprint>> fingerprints = new HashMap<>();
	private ChangeReporter changeReporter;
	private int changes;
	
	public ChangeDetector(ChangeReporter changeReporter) {
		this.changeReporter = changeReporter;
		this.changes = 0;
	}
	
	public void reportConnection(ClientHelloFingerprint chf, ServerFingerprint sf) {
		if (fingerprints.containsKey(chf)) {
			List<ServerFingerprint> previousFingerprints = fingerprints.get(chf);

			if(previousFingerprints.contains(sf)) {
				// We have seen this!
				reportFingerprintUpdate(chf, sf);
				return;
			}
			// A new different fingerprint for this ClientFingerprint
			reportFingerprintChange(chf, sf, previousFingerprints);
			previousFingerprints.add(sf);
		} else {
			// the ClientHelloFingerprint is not yet in fingerprints, add it
			List<ServerFingerprint> sfs = new ArrayList<>(1);
			sfs.add(sf);
			reportFingerprintUpdate(chf, sf);
			fingerprints.put(chf, sfs);
		}
	}

	/**
	 * either we see this chf for the first time, or we have already seen both together
     *
     * TODO: distinguish new and updated fingerprint
	 */
	private void reportFingerprintUpdate(ClientHelloFingerprint chf,
	                                     ServerFingerprint sf) {
		changeReporter.reportUpdate(chf, sf);
	}

	/**
	 * this chf + sf combination is new to us
	 * @param previousFingerprints
	 *      the ServerFingerprints we have already seen in conjunction with chf
	 */
	private void reportFingerprintChange(ClientHelloFingerprint chf,
	                                  ServerFingerprint sf,
	                                  List<ServerFingerprint> previousFingerprints) {
		changeReporter.reportChange(chf, sf, previousFingerprints);
		changes++;
	}
	
	public String toString() {
		return String.format("ChangeDetector: saw %d ClientFingerprints, "
				+ "and %d ServerFingerprint changes.",
                fingerprints.size(), this.changes);
    }
}
