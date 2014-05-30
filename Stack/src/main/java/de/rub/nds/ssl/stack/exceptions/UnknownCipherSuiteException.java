package de.rub.nds.ssl.stack.exceptions;

/**
 * @author Jonathan Biegert azrdev@qrdn.de
 */
public class UnknownCipherSuiteException extends IllegalArgumentException {

    public UnknownCipherSuiteException(int id) {
        super(String.format("Cipher suite 0x%x not recognized.", id));
    }
}
