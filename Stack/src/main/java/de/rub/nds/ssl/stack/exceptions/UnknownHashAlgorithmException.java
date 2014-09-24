package de.rub.nds.ssl.stack.exceptions;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownHashAlgorithmException extends IllegalArgumentException {
    public UnknownHashAlgorithmException(byte id) {
        super(String.format("Hash Algorithm with id 0x%02x not recognized.", id));
    }
}
