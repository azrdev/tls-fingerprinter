package de.rub.nds.ssl.stack.exceptions;

import de.rub.nds.ssl.stack.Utility;

/**
 * @author Jonathan Biegert azrdev@qrdn.de
 */
public class UnknownCipherSuiteException extends IllegalArgumentException {

    public UnknownCipherSuiteException(final byte[] id) {
        super(String.format("Cipher suite %s not recognized.",
                Utility.bytesIdToHex(id)));
    }
}
