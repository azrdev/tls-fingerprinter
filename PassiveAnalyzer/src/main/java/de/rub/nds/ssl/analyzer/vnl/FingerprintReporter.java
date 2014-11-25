package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import java.util.List;

public interface FingerprintReporter {
    /**
     * A new fingerprint for the {@link SessionIdentifier}.
     */
	public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             List<TLSFingerprint> previousFingerprints);

    /**
     * An occurrence of a {@link SessionIdentifier} and {@link TLSFingerprint} we have already seen
     * together.
     */
	public void reportUpdate(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint);

    /**
     * A new {@link SessionIdentifier} has been seen (and the given {@link TLSFingerprint}.
     */
    public void reportNew(SessionIdentifier sessionIdentifier,
                          TLSFingerprint tlsFingerprint);

    /**
     * A new {@link TLSFingerprint} generated not from on-the-wire data, but from code.
     * The {@link SessionIdentifier} might be new or updated, it can also be generated.
     */
    public void reportArtificial(SessionIdentifier sessionIdentifier,
                                 TLSFingerprint fingerprint);
}
