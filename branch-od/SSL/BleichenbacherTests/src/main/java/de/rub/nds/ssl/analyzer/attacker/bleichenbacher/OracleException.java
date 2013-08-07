package de.rub.nds.ssl.analyzer.attacker.bleichenbacher;

import de.rub.nds.ssl.stack.exceptions.ACommonException;
import org.apache.log4j.lf5.LogLevel;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class OracleException extends ACommonException {
    
    /**
     *
     * @param exceptionMessage
     * @param exceptionToWrap
     * @param exceptionLogLevel
     */
    public OracleException(final String exceptionMessage,
            final Exception exceptionToWrap, final LogLevel exceptionLogLevel) {
        super(exceptionMessage, exceptionToWrap, exceptionLogLevel);
    }

}
