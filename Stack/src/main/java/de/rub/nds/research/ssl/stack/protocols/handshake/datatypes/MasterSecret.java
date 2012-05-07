package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.commons.PseudoRandomFunction;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;

/**
 * MasterSecret part - as defined in RFC-2246
 * 
 * @author  Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Feb 16, 2012
 */
public class MasterSecret extends APubliclySerializable{
	
	/**
     * Minimum length of the encoded form
     */
    public final static int LENGTH_MINIMUM_ENCODED = 48;
    
    /**
     * Master secret label
     */
    private final static String MASTER_SECRET_LABEL = "master secret";
    
    private byte [] master_secret=null;
    
    public MasterSecret(byte [] clientRandom, byte [] serverRandom, byte [] encodedPMS) throws InvalidKeyException {
    	byte [] randomValues = this.concatRandomValues(clientRandom, serverRandom);
    	PseudoRandomFunction prf = new PseudoRandomFunction(LENGTH_MINIMUM_ENCODED);
    	master_secret = prf.generatePseudoRandomValue(encodedPMS, MASTER_SECRET_LABEL, randomValues);
    }
    
    /**
	 * Creates the seed value which is an input parameter of the PRF function.
	 * @param label
	 * @param clientRandom
	 * @param serverRandom
	 * @return seed
	 */
	private byte[] concatRandomValues(byte [] clientRandom, byte [] serverRandom){
		byte [] seed = new byte[clientRandom.length+serverRandom.length];
		int pointer=0;
		//copy the client random to the array
		System.arraycopy(clientRandom, 0, seed, pointer, clientRandom.length);
		pointer += clientRandom.length;
		System.arraycopy(serverRandom, 0, seed, pointer, serverRandom.length);
		return seed;
	}
	
	/**
	 * Set the bytes of the master secret
	 * @param secret_bytes The bytes of the master secret
	 */
	public void setMasterSecret(final byte [] secret_bytes){
		if (master_secret == null || master_secret.length != LENGTH_MINIMUM_ENCODED) {
			throw new 
			IllegalArgumentException("Master secret must be exactly 48 Bytes "
					+ LENGTH_MINIMUM_ENCODED + " bytes!");
		}
		// deep copy
		System.arraycopy(secret_bytes, 0, master_secret, 0, secret_bytes.length);
	}
	
	public byte [] getMasterSecret(){
		// deep copy
        byte[] copy = new byte[LENGTH_MINIMUM_ENCODED];
        System.arraycopy(master_secret, 0, copy, 0, LENGTH_MINIMUM_ENCODED);
        return copy;
	}

	@Override
	public byte[] encode(boolean chained) {
		byte[] masterSecret = new byte[LENGTH_MINIMUM_ENCODED];
		System.arraycopy(master_secret, 0, masterSecret, 0, master_secret.length);
		return masterSecret;
	}

	@Override
	public void decode(byte[] message, boolean chained) {
		// TODO Auto-generated method stub
		
	}

}
