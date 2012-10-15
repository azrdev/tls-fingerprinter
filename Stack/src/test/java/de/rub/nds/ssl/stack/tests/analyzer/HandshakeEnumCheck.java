package de.rub.nds.ssl.stack.tests.analyzer;

import java.util.ArrayList;

import org.testng.Reporter;

import de.rub.nds.ssl.stack.tests.analyzer.common.ETLSImplementation;
import de.rub.nds.ssl.stack.tests.analyzer.common.ScoreCounter;
import de.rub.nds.ssl.stack.trace.Message;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;

/**
 * Check if handshake enumeration is applied
 * for handshake messages.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 */
public class HandshakeEnumCheck extends AFingerprintAnalyzer {

    @Override
    public void analyze(final ArrayList<Message> traceList) {
        ScoreCounter counter = ScoreCounter.getInstance();
		for (int i = 0; i < traceList.size(); i++) {
			Message currentTrace = traceList.get(i);
			if (currentTrace.getState() == EStates.SERVER_HELLO) {
				/*Check if a message is part of a handshake enumeration
				 * and assign a score for an implementation.
				 */
				if (currentTrace.isContinued()) {
					counter.countResult(ETLSImplementation.JSSE_STANDARD, 2);
					Reporter.log("Found fingerprint hit for " +
					ETLSImplementation.JSSE_STANDARD.name());
				}
				else {
					counter.countResult(ETLSImplementation.GNUTLS, 1);
					counter.countResult(ETLSImplementation.OPENSSL, 1);
					Reporter.log("Found fingerprint hit for "
					+ ETLSImplementation.GNUTLS.name()
					+ " and " + ETLSImplementation.OPENSSL.name());
				}
			}
		}
	}

}
