package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.List;

public interface ChangeReporter {
	public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint,
                             List<TLSFingerprint> previousFingerprints);
	public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint);
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint);
}
