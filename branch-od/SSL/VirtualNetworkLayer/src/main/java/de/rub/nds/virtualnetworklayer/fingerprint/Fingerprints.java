package de.rub.nds.virtualnetworklayer.fingerprint;

/**
 * Registry of all fingerprints.
 * {@link Enum#ordinal()} is used as id.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public enum Fingerprints {
    Mtu,
    Tcp;

    public int getId() {
        return this.ordinal();
    }
}
