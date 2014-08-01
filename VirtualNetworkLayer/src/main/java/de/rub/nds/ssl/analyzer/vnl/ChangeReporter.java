package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;

import java.util.List;

public interface ChangeReporter {
	public void reportChange(Fingerprint.Signature cs, ServerFingerprint sf, List<ServerFingerprint> previousResponses);
	public void reportUpdate(Fingerprint.Signature cs, ServerFingerprint sf);
}
