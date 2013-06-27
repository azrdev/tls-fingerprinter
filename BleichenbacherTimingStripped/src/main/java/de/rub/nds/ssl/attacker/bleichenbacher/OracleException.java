package de.rub.nds.ssl.attacker.bleichenbacher;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class OracleException extends Exception {
    
    /**
     *
     * @param exceptionMessage
     * @param exceptionToWrap
     * @param exceptionLogLevel
     */
    public OracleException(final String exceptionMessage,
            final Exception exceptionToWrap) {
        super(exceptionMessage, exceptionToWrap);
    }

}
