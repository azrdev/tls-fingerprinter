package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

/**
 * Interface for cipher computation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de Apr 23, 2012
 */
public interface IGenericCipher {

    /**
     * {@inheritDoc}
     */
    void decode(final byte[] message, final boolean chained);

    /**
     * {@inheritDoc}
     */
    byte[] encode(final boolean chained);
}
