package de.rub.nds.research.ssl.stack.protocols.commons;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.crypto.MACComputation;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;

/**
 * Encrypted data record
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Mar 15, 2012
 */
public class DataRecord extends ARecordFrame {

	/**
	 * The encrypted record data.
	 */
	private byte [] encryptedData = null;
	/**
	 * The decrypted record data.
	 */
	private byte [] decryptedData = null;
	/**
	 * The MAC of the data.
	 */
	private byte [] macData = null;

	/**
     * Initializes an encrypted data record
     * @param message SSL data record in encrypted form
     * @param chained Decode single or chained with underlying frames
     */
    public DataRecord(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a data record with a specific content type
     * @param version Protocol version
     * @param message Bytes of the message
     * @param type The content type
     */
	public DataRecord(final EProtocolVersion version,
			byte [] message, EContentType type){
		super(type, version);
		super.setPayload(message);
	}

	/**
	 * Initializes a application data record
	 * @param version Protocol version
	 * @param message Bytes of the message
	 */
	public DataRecord(final EProtocolVersion version,
			final byte [] message) {
		super(EContentType.APPLICATION, version);
		super.setPayload(message);
	}

	/**
	 * Decrypt the data of an encrypted data record
	 * @param key Symmetric key
	 * @param cipherName Name of the symmetric cipher
	 * @param iv Initialization vector for ciphertext computation
	 */
	public byte [] decryptData(SecretKey key,
			String cipherName, byte [] iv) {
    	Cipher blockCipher;
		try {
			blockCipher = Cipher.getInstance(cipherName+"/CBC/NoPadding");
			AlgorithmParameters params = AlgorithmParameters.getInstance(cipherName);
	    	IvParameterSpec iVector = new IvParameterSpec(iv);
	    	params.init(iVector);
			blockCipher.init(Cipher.DECRYPT_MODE, key, params);
			//first decrypt the data
			decryptedData = blockCipher.doFinal(super.getPayload());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return decryptedData;
    }

	/**
	 * Concatenate data and MAC, add padding and encrypt data
	 * @param key Symmetric key
	 * @param cipherName Name of the symmetric cipher
	 * @param iv Initialization vector for ciphertext computation
	 */
	public void encryptData(SecretKey key,
			String cipherName, byte [] iv) {
    	Cipher blockCipher = null;
		try {
			blockCipher = Cipher.getInstance(cipherName+"/CBC/NoPadding");
			AlgorithmParameters params = AlgorithmParameters.getInstance(cipherName);
	    	IvParameterSpec iVector = new IvParameterSpec(iv);
	    	params.init(iVector);
			blockCipher.init(Cipher.ENCRYPT_MODE, key, params);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		//concatenate data and MAC
		int pointer = 0;
		int payloadLength = super.getPayload().length;
		byte [] tmp = new byte[macData.length + payloadLength];
		System.arraycopy(super.getPayload(), 0, tmp, pointer, payloadLength);
		pointer += payloadLength;
		System.arraycopy(macData, 0, tmp, pointer, macData.length);
		byte [] paddedData = null;
		int blockSize = blockCipher.getBlockSize();
		paddedData = this.addPadding(tmp, blockSize);
		//encrypt the data
		try {
			encryptedData = blockCipher.doFinal(paddedData);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
    }

	/**
	 * Initialize block cipher for ciphertext computation
	 * @param key Symmetric key for encryption
	 * @param cipherName Symmetric cipher
	 * @param iv Initialization vector
	 * @return Cipher object
	 */
	public final Cipher initBlockCipher(final SecretKey key,
			final String cipherName, final byte [] iv) {
		Cipher blockCipher = null;
		AlgorithmParameters params = null;
		try {
			blockCipher =
				Cipher.getInstance(cipherName + "/CBC/NoPadding");
			params = AlgorithmParameters.getInstance(cipherName);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
    	IvParameterSpec iVector = new IvParameterSpec(iv);
    	try {
			params.init(iVector);
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		try {
			blockCipher.init(Cipher.ENCRYPT_MODE, key, params);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return blockCipher;
	}

	/**
	 * Concatenates the record payload and the MAC
	 * @param data Record payload
	 * @param mac MAC of the payload
	 * @return Concatenated data
	 */
	public final byte [] concatenateDataMAC(final byte [] data,
			final byte [] mac) {
		int pointer = 0;
		int payloadLength = data.length;
		byte [] tmp = new byte[mac.length + payloadLength];
		//add payload
		System.arraycopy(data, 0, tmp, pointer, payloadLength);
		pointer += payloadLength;
		//add the MAC
		System.arraycopy(mac, 0, tmp, pointer, mac.length);
		return tmp;
	}
	
	/**
	 * Compute the MAC of the payload
	 * @param key Secret key for MAC computation
	 * @param macName MAC algorithm
	 * @return MAC of the payload
	 */
	public byte [] computePayloadMAC(SecretKey key, String macName){
		byte [] payload = super.getPayload();
		byte [] protocolVersion = super.getProtocolVersion().getId();
		byte contentType = super.getContentType().getId();
		byte [] payloadLength = super.buildLength(payload.length, 2);
		MACComputation comp = new MACComputation(key,macName);
		macData = comp.computeMAC(protocolVersion, contentType, payloadLength, payload);
		return macData;
	}
    
    public byte [] encode(final boolean chained){
    	byte [] data = new byte [encryptedData.length];
		System.arraycopy(encryptedData, 0, data, 0, encryptedData.length);
		super.setPayload(data);
		return chained ? super.encode(true) : data;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
    	byte[] tmpBytes;
        byte[] payloadCopy;

        if(chained){
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        
        // payload already deep copied
        payloadCopy = getPayload();

        // 1. extract verify data 
        tmpBytes = new byte[payloadCopy.length];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        setEncryptedData(tmpBytes);
    }
    
    /**
     * Set the data of the record in encrypted form
     * @param encryptedData Encrypted data
     */
    public void setEncryptedData(byte [] encryptedData) {
    	this.encryptedData=encryptedData;
    }
    
    /**
     * Padding as described in Chapter 6.2.3.2  of RFC 2246
     * @param data Data which should be padded
     * @param blockSize Block size of the cipher
     * @return Padded data which is a multiple of the block size
     */
    public static byte [] addPadding(byte [] data, int blockSize) {
    	int padLength = 0;
    	if ((data.length%blockSize) != 0) {
    		padLength = blockSize - (data.length%blockSize);
    	}
    	else {
    		padLength = blockSize;
    	}
    	byte length = (byte)(padLength-1);
    	byte[] padding = new byte[padLength];
    	for (int i = 0; i < padding.length; i++) {
    		padding[i] = length;
    	}
    	int pointer = 0;
    	byte [] paddedData = new byte [data.length + padLength];
    	System.arraycopy(data, 0, paddedData, pointer, data.length);
    	pointer += data.length;
    	System.arraycopy(padding, 0, paddedData, pointer, padLength);
    	return paddedData;
    }

}
