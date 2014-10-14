package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.List;

public interface FingerprintReporter {
	public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint,
                             List<TLSFingerprint> previousFingerprints);
	public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint);
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint);
}
