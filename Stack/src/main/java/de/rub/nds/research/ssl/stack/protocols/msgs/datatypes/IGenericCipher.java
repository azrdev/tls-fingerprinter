package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

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
