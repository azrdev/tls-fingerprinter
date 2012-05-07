package de.rub.nds.research.ssl.stack.protocols.msgs;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherType;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.GenericStreamCipher;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.IGenericCipher;

/**
 * TLSCiphertext message as defined in Chapter 6.2.3 of RFC 2246
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Apr 21, 2012
 */
public class TLSCiphertext extends ARecordFrame {

	/**The cipher*/
	private IGenericCipher genericCipher = null;


	/**
     * Initializes an encrypted data record
     * @param message SSL data record in encrypted form
     * @param param Security parameters of this handshake
     * @param chained Decode single or chained with underlying frames
     */
    public TLSCiphertext(final byte[] message, final boolean chained) {
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
	public TLSCiphertext(final EProtocolVersion version,
			final EContentType type) {
		super(type, version);
	}
	
	/**
	 * Initializes a application data record
	 * @param version Protocol version
	 * @param param The security parameters
	 */
	public TLSCiphertext(final EProtocolVersion version) {
		super(EContentType.APPLICATION, version);
	}

	/**
	 * Set the ciphertext
	 * @param cipher The cipher
	 */
	public final void setGenericCipher(final IGenericCipher cipher) {
		setGenericCipher(cipher.encode(false));
	}

	/**
     * Get the cipher
     * @return Specific cipher type object
     */
    public final IGenericCipher getGenericCipher() {
        IGenericCipher genericCipher = null;
        SecurityParameters param = SecurityParameters.getInstance();
        byte[] tmp;

        tmp = this.genericCipher.encode(false);
        switch (param.getCipherType()) {
            case STREAM:
                genericCipher = new GenericStreamCipher(tmp);
                break;
            case BLOCK:
               genericCipher = new GenericBlockCipher(tmp);
                break;
            default:
                break;
        }

        return genericCipher;
    }

	/**
     * Set encrypted payload depend on cipher type.
     * @param payload Encrypted payload
     */
    public final void setGenericCipher(final byte[] payload) {
        byte[] tmp = new byte[payload.length];
        System.arraycopy(payload, 0, tmp, 0, tmp.length);
        SecurityParameters param = SecurityParameters.getInstance();
        setPayload(tmp);
        switch (param.getCipherType()) {
            case STREAM:
                this.genericCipher = new GenericStreamCipher(tmp);
                break;
            case BLOCK:
                this.genericCipher = new GenericBlockCipher(tmp);
                break;
            default:
                break;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
	public final byte [] encode(final boolean chained) {
    	byte[] encCipher = this.genericCipher.encode(false);

        super.setPayload(encCipher);
        return chained ? super.encode(true) : encCipher;
    }

    /**
     * {@inheritDoc}
     */
    @Override
	public final void decode(final byte[] message, final boolean chained) {
    	byte[] tmpBytes;
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // 1. extract verify data
        tmpBytes = new byte[payloadCopy.length];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        setGenericCipher(tmpBytes);
    }

}
