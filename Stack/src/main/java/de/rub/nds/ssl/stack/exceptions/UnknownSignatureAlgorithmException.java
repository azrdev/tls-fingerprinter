package de.rub.nds.ssl.stack.exceptions;

import de.rub.nds.ssl.stack.Utility;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownSignatureAlgorithmException extends IllegalArgumentException {
    public UnknownSignatureAlgorithmException(byte id) {
        super(String.format("Signature Algorithm with id 0x%02x not recognized.", id));
    }
}
