package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.List;

/**
 * Check if handshake enumeration is applied for handshake messages.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 */
public class HandshakeEnumCheck implements IFingerprinter {

    @Override
    public void analyze(final List<MessageContainer> traceList) {
        ScoreCounter counter = ScoreCounter.getInstance();
        for (int i = 0; i < traceList.size(); i++) {
            MessageContainer currentTrace = traceList.get(i);
            if (currentTrace.getState() == EStates.SERVER_HELLO) {
                /*Check if a message is part of a handshake enumeration
                 * and assign a score for an implementation.
                 */
                if (currentTrace.isContinued()) {
                    // TODO quick fix -- JSSE_STANDARD ersetzt
                    // @ Eugen kannst du das korrekt anpassen? Die Server dürften erreichbar sein
                    counter.countResult(ETLSImplementation.JDK_6_35, 2);
                    // TODO logging
// Reporter.log("Found fingerprint hit for " + ETLSImplementation.JSSE_STANDARD.name());
                } else {
                    counter.countResult(ETLSImplementation.GNUTLS, 1);
                    // TODO quick fix -- JSSE_STANDARD durch ersetzt
                    // @ Eugen kannst du das korrekt anpassen? Die Server dürften erreichbar sein
                    counter.countResult(ETLSImplementation.OPENSSL_1_0_1, 1);
                    // TODO logging
// Reporter.log("Found fingerprint hit for " + ETLSImplementation.GNUTLS.name() + " and " + ETLSImplementation.OPENSSL.name());
                }
            }
        }
    }

    @Override
    public void init(AParameters parameters) {
        // nothing to do
    }
}
