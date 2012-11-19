package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.List;

public class PrintingChangeReporter implements ChangeReporter {

	@Override
	public void reportChange(ClientHelloFingerprint chf,
			ServerFingerprint sf,
			List<ServerFingerprint> previousResponses) {
		System.out.println("WARNING: Change detected!");
		System.out.println("ClientHelloFingerprint is: " + chf);
		System.out.println("New Server Response is: " + sf);
		System.out.println("Previous responses were:");
		for (ServerFingerprint serverHelloFingerprint : previousResponses) {
			System.out.println(serverHelloFingerprint);
		}
		System.out.println("End of responses");
	}

}
