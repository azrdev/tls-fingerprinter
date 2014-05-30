package de.rub.nds.ssl.stack.exceptions;

/**
 * @author Jonathan Biegert azrdev@qrdn.de
 */
public class UnknownTLSExtensionException extends IllegalArgumentException {
    public UnknownTLSExtensionException(int type) {
        super(String.format("TLS Extension of type 0x%04x not recognized.", type));
    }
}
