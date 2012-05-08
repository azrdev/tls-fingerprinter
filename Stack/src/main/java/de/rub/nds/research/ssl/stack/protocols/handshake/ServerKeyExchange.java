package de.rub.nds.research.ssl.stack.protocols.handshake;

import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.IExchangeKeys;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ServerDHParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ServerRSAParams;
import de.rub.nds.research.ssl.stack.protocols.msgs.datatypes.TLSSignature;


/**
 * Defines the ServerKeyExchange message of SSL/TLS as defined in RFC 2246
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Apr 17, 2012
 */
public class ServerKeyExchange extends AHandshakeRecord {
	
	/**Key exchange algorithm used in the handshake.*/
    private EKeyExchangeAlgorithm keyExchangeAlgorithm;
    /**Exchange keys.*/
    private IExchangeKeys exchangeKeys;
    /**Signature of the parameters.*/
    private TLSSignature signature;

	/**
     * Initializes a ServerKeyExchange message as defined in RFC 2246.
     * @param message ServerKeyExchange message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public ServerKeyExchange(final byte[] message,
            final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        this.keyExchangeAlgorithm =
                keyParams.getKeyExchangeAlgorithm();
        this.decode(message, chained);
    }
    
    /**
     * Initializes a ServerKeyExchange message as defined in RFC 2246.
     *
     * @param protocolVersion Protocol version of this message
     * @param exchangeAlgorithm Key exchange algorithm to be used
     */
    public ServerKeyExchange(final EProtocolVersion protocolVersion,
    		final EKeyExchangeAlgorithm exchangeAlgorithm) {
    	super(protocolVersion, EMessageType.SERVER_KEY_EXCHANGE);
    	this.keyExchangeAlgorithm =
                EKeyExchangeAlgorithm.valueOf(exchangeAlgorithm.name());
    	 KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
    	 keyParams.setKeyExchangeAlgorithm(exchangeAlgorithm);
    }
    
    /**
     * Get the exchange keys
     *
     * @return Key exchange keys of this message
     */
    public final IExchangeKeys getExchangeKeys() {
        IExchangeKeys keys = null;
        byte[] tmp;

        tmp = this.exchangeKeys.encode(false);
        switch (this.keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                keys = new ServerDHParams(tmp);
                break;
            case RSA:
                keys = new ServerRSAParams(tmp);
                break;
            default:
                break;
        }

        return keys;
    }
    
    /**
     * {@inheritDoc}
     */
    public final void decode(final byte[] message, final boolean chained) {
    	byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        
        // payload already deep copied
        payloadCopy = getPayload();
        
        switch (keyExchangeAlgorithm) {
            case DIFFIE_HELLMAN:
                exchangeKeys = new ServerDHParams(payloadCopy);
                signature = new TLSSignature(payloadCopy);
                break;
            case RSA:
                exchangeKeys = new ServerRSAParams(payloadCopy);
                signature = new TLSSignature(payloadCopy);
                break;
            default:
                break;
        }

    }
    

}
