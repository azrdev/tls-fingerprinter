package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import sun.security.rsa.RSACore;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;

public class TLSSignature extends APubliclySerializable {
	
	private ESignatureAlgorithm sigAlgorithm;
	/**
	 * Length of the length field.
	 */
	private static final int LENGTH_LENGTH_FIELD = 2;
	/**
	 * Servers key exchange parameters.
	 */
	private byte[] serverParams;
	/**
	 * Signature value
	 */
	private byte[] sigValue = null;
	
	public TLSSignature(ESignatureAlgorithm sigAlgorithm) {
		this.sigAlgorithm=sigAlgorithm;
	}
	
	public TLSSignature(byte[] message){
		KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
		this.sigAlgorithm = keyParams.getSignatureAlgorithm();
		this.decode(message, false);
	}
	
	/**
	 * Check the signature of the passed key exchange parameters.
	 * Signature checking for RSA and DSA is supported. If RSA is
	 * used signature was built over concatenated MD5 and SHA1 hashes. 
	 * @param signature Signed server key exchange parameters
	 * @return True if signature was successfully verified
	 */
	public boolean checkSignature(byte [] signature) {
		KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
		boolean valid = false;
		if (keyParams.getSignatureAlgorithm() == ESignatureAlgorithm.RSA){
			valid = checkRSASignature(signature, keyParams.getPublicKey());
		} else {
			/*
			 * DSA signature checking to be implemented
			 */
		}
		return valid;
	}
	
	/**
	 * 
	 */
	public boolean checkRSASignature(byte[] signature, PublicKey pk) {
		SecurityParameters params = SecurityParameters.getInstance();
		byte[] clientRandom = params.getClientRandom();
		byte[] serverRandom = params.getServerRandom();
		byte[] serverParams = getServerParams();
		byte[] md5Hash = new byte[16];
		byte[] sha1Hash = new byte [20];
		byte[] concat = new byte [36];
		md5Hash = md5_hash(clientRandom, serverRandom,
				serverParams);
		sha1Hash = sha1_hash(clientRandom, serverRandom,
				serverParams);
		//concatenate the two hashes
		int pointer = 0;
		System.arraycopy(md5Hash, 0, concat, pointer, md5Hash.length);
		pointer += md5Hash.length;
		System.arraycopy(sha1Hash, 0, concat, pointer, sha1Hash.length);
		//compute signature
        byte [] msg = null;
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsaPK = (RSAPublicKey) pk;
            try {
            	msg = RSACore.rsa(signature, rsaPK);
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
        }
        byte [] recHash = new byte[36];
        System.arraycopy(msg, msg.length - recHash.length, recHash, 0, recHash.length);
        return  Arrays.equals(recHash, concat);
	}
	
	public final byte[] md5_hash(byte [] clientRandom,
			byte[] serverRandom, byte[] serverParams) {
		MessageDigest md5 = null;
		byte [] input = null;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		input = concatenateParameter(clientRandom, serverRandom,
				serverParams);
		md5.update(input);
		return md5.digest();
	}
	
	public final byte[] sha1_hash(byte [] clientRandom,
			byte[] serverRandom, byte[] serverParams) {
		MessageDigest sha1 = null;
		byte [] input = null;
		try {
			sha1 = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		input = concatenateParameter(clientRandom, serverRandom,
				serverParams);
		sha1.update(input);
		return sha1.digest();
	}
	
	private final byte [] concatenateParameter(byte [] clientRandom,
			byte[] serverRandom, byte[] serverParams) {
		//concatenate the passed parameters
		int pointer = 0;
		byte [] tmp = new byte [clientRandom.length +
		                        serverRandom.length + serverParams.length];
		System.arraycopy(clientRandom, 0, tmp, pointer, clientRandom.length);
		pointer += clientRandom.length;
		System.arraycopy(serverRandom, 0, tmp, pointer, serverRandom.length);
		pointer += serverRandom.length;
		System.arraycopy(serverParams, 0, tmp, pointer, serverParams.length);
		return tmp;
	}

	@Override
	public byte[] encode(boolean chained) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void decode(byte[] message, boolean chained) {
		int extractedLength;
		int sigLength = 0;
		byte[] tmpBytes;
		// deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);
        
        if (sigAlgorithm == ESignatureAlgorithm.anon) {
        	/*if signature algorithm is set to "anonymous"
        	no signature value was added*/ 
        	setSignatureValue(new byte[0]);
        }
        else {
        	int pointer = 0;
        	for (int i=0; i < 4; i++) {
        		extractedLength = extractLength(paramCopy, pointer, LENGTH_LENGTH_FIELD);
            	pointer += LENGTH_LENGTH_FIELD + extractedLength;
            	if (pointer == paramCopy.length) {
            		sigLength = extractedLength;
            		pointer -= extractedLength;
            		break;
            	}
        	}
        	// extract signature 
        	tmpBytes = new byte[sigLength];
        	System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
        	setSignatureValue(tmpBytes);
        	//extract serverParams
        	byte[] serverParams = new byte[paramCopy.length-(sigLength+2)];
        	System.arraycopy(paramCopy, 0, serverParams, 0, paramCopy.length - (sigLength+2));
        	setServerParams(serverParams);
        	if (checkSignature(tmpBytes) != true){
        		try {
					throw new Exception("Signature invalid");
				} catch (Exception e) {
					e.printStackTrace();
				}
        	}
        }
	}
	
	private byte[] getServerParams() {
		return serverParams;
	}
	
	private void setServerParams(byte[] serverParams) {
		this.serverParams=serverParams;
	}

	
	public byte[] getSignatureValue() {
		return sigValue;
	}

	public void setSignatureValue(byte[] sigValue) {
		this.sigValue = sigValue;
	}

}
