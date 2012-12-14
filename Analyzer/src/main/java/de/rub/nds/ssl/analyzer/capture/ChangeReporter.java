package de.rub.nds.ssl.analyzer.capture;

import java.util.List;

public interface ChangeReporter {
	public void reportChange(ClientHelloFingerprint chf, ServerFingerprint sf, List<ServerFingerprint> previousResponses);

}
