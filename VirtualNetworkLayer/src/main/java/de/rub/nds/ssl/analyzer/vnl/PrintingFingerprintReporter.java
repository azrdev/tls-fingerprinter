package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.List;

public class PrintingFingerprintReporter implements FingerprintReporter {

	@Override
	public void reportChange(SessionIdentifier sessionIdentifier,
			TLSFingerprint fingerprint,
			List<TLSFingerprint> previousFingerprints) {
		System.out.println("********************************************************************");
		System.out.println("WARNING: Change detected for " + sessionIdentifier);
        for (int i = 0, ps = previousFingerprints.size(); i < ps; i++) {
            TLSFingerprint previous = previousFingerprints.get(i);
            System.out.println(fingerprint.difference(previous,
                    String.format("previous #%d", i+1)));
        }
		System.out.println("********************************************************************");
	}

	@Override
	public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
		System.out.println(String.format("Saw a Fingerprint again:\n%s\n%s",
                sessionIdentifier.toString(),
                fingerprint.toString()));
	}

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
		System.out.println(String.format("Saw a new Fingerprint:\n%s\n%s",
                sessionIdentifier.toString(),
                fingerprint.toString()));
    }
}
