package de.rub.nds.ssl.analyzer.vnl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChangeDetector {
	
	private Map<ClientHelloFingerprint, List<ServerFingerprint>> fingerprints;
	private ChangeReporter changeReporter;
	private int changes;
	
	public ChangeDetector(ChangeReporter changeReporter) {
		this.fingerprints = new HashMap<ClientHelloFingerprint, List<ServerFingerprint>>();
		this.changeReporter = changeReporter;
		this.changes = 0;
	}
	
	public void reportConnection(ClientHelloFingerprint chf, ServerFingerprint sf) {
		List<ServerFingerprint> previousFingerprints = fingerprints.get(chf);
		if (previousFingerprints == null) {
			ArrayList<ServerFingerprint> ar = new ArrayList<ServerFingerprint>();
			ar.add(sf);
			fingerprints.put(chf, ar);
		} else {
			for (ServerFingerprint serverFingerprint : previousFingerprints) {
				if (serverFingerprint.equals(sf)) {
					// We have seen this!
					return;
				}
			}
			// A new fingerprint, and not the first one!
			changeReporter.reportChange(chf, sf, previousFingerprints);
			changes++;
			previousFingerprints.add(sf);
		}
		
	}
	
	public String toString() {
		return String.format("ChangeDetector: %d different fingerprints seen, " +
                "%d changes so far.",
                this.changes, fingerprints.size());
    }
	
	

}
