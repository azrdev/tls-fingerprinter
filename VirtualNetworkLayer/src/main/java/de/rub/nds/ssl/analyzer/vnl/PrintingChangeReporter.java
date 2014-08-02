package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.List;

public class PrintingChangeReporter implements ChangeReporter {

	@Override
	public void reportChange(SessionIdentifier sessionIdentifier,
			TLSFingerprint fingerprint,
			List<TLSFingerprint> previousFingerprints) {
		System.out.println("********************************************************************");
		System.out.println("WARNING: Change detected for host");//: " + chf.getHostName());
		// System.out.println("ClientHelloFingerprint is: " + chf);
		// System.out.println("New Server Response is: " + sf);
		System.out.println("Difference to previous:");
		for (TLSFingerprint serverHelloFingerprint : previousFingerprints) {
			//System.out.println(serverHelloFingerprint.getDifference(sf));
			// System.out.println(serverHelloFingerprint);
		}
		System.out.println("End of responses");
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
