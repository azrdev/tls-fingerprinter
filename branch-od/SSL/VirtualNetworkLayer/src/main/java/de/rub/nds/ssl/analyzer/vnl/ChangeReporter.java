package de.rub.nds.ssl.analyzer.vnl;

import java.util.List;

public interface ChangeReporter {
	public void reportChange(ClientHelloFingerprint chf, ServerFingerprint sf, List<ServerFingerprint> previousResponses);

}
