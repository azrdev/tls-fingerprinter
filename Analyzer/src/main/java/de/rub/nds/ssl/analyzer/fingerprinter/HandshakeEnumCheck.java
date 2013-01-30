package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.AnalyzerResult;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Check if handshake enumeration is applied for handshake messages.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 */
public final class HandshakeEnumCheck implements IFingerprinter {

    /**
     * Log4j logger initialization.
     */
//    private static Logger logger = Logger.getRootLogger();

    @Override
    public AnalyzerResult analyze(final List<MessageContainer> traceList) {
        AnalyzerResult result = new AnalyzerResult();
        ScoreCounter counter = new ScoreCounter();
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
//                    logger.info("Found fingerprint hit for "
//                            + ETLSImplementation.JDK_6_35);
                } else {
                    counter.countResult(ETLSImplementation.GNUTLS, 1);
//                    logger.info("Found fingerprint hit for "
//                            + ETLSImplementation.GNUTLS);
                    // TODO quick fix -- JSSE_STANDARD durch ersetzt
                    // @ Eugen kannst du das korrekt anpassen? Die Server dürften erreichbar sein
                    counter.countResult(ETLSImplementation.OPENSSL_1_0_1, 1);
//                    logger.info("Found fingerprint hit for "
//                            + ETLSImplementation.OPENSSL_1_0_1);
                }
            }
        }
        
        result.setScoreCounter(counter);
        return result;
    }

    @Override
    public void init(final AParameters parameters) {
        // nothing to do
    }
}
