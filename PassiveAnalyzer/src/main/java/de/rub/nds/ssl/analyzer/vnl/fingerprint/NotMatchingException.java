package de.rub.nds.ssl.analyzer.vnl.fingerprint;

/**
 * Throw whenever a {@link Fingerprint} should be created on a connection without the
 * fingerprinted data type (e.g. TLSFingerprint without TLS handshake)
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class NotMatchingException extends IllegalArgumentException {
    public NotMatchingException() {
        super("The supplied Connection did not contain elements " +
              "to create such fingerprint.");
    }
}
