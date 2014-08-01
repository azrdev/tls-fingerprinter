package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;

import java.util.List;

public class PrintingChangeReporter implements ChangeReporter {

	@Override
	public void reportChange(Fingerprint.Signature cs,
			ServerFingerprint sf,
			List<ServerFingerprint> previousResponses) {
		System.out.println("********************************************************************");
		System.out.println("WARNING: Change detected for host");//: " + chf.getHostName());
		// System.out.println("ClientHelloFingerprint is: " + chf);
		// System.out.println("New Server Response is: " + sf);
		System.out.println("Difference to previous:");
		for (ServerFingerprint serverHelloFingerprint : previousResponses) {
			//System.out.println(serverHelloFingerprint.getDifference(sf));
			// System.out.println(serverHelloFingerprint);
		}
		System.out.println("End of responses");
	}

	@Override
	public void reportUpdate(Fingerprint.Signature clientSignature, ServerFingerprint sf) {
		System.out.println(String.format("Saw a ServerFingerprint (again): " +
                        "{ClientFingerprint\n%s} => {%s}",
                clientSignature.toString(),
                sf.toString()));
	}
}
