package de.rub.nds.ssl.stack.protocols.handshake.extensions.exceptions;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownCertificateStatusTypeException extends IllegalArgumentException {
    public UnknownCertificateStatusTypeException(byte id) {
        super(String.format("Unknown CertificateStatus Type 0x%02x", id));
    }
}
