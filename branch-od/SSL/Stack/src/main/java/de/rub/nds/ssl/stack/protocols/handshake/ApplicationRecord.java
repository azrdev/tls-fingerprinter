package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines all Application Messages of SSL/TLS
 *
 * @author Oliver Domke - oliver.domke@rub.de
 * @version 0.1
 *
 * Aug 15, 2013
 */
public class ApplicationRecord extends ARecordFrame {

    /**
     * Length of MAC
     */
    private static final int LENGTH_MAC_FIELD = 20;

    /**
     * Dummy constructor - used by the mandatory super() calls
     */
    public ApplicationRecord() {
        super();
        this.setContentType(EContentType.APPLICATION);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param version Protocol version of this handshake message
     * @param message Encoded handshake message
     * @param type Message type of this handshake message
     */
    public ApplicationRecord(final EProtocolVersion version, final byte[] message) {
        super(EContentType.APPLICATION, version, message);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param message Encoded handshake message
     * @param chained Decode single or chained with underlying frames
     */
    public ApplicationRecord(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes a handshake record as defined in RFC 2246
     *
     * @param version Protocol version
     * @param type Message type
     */
    protected ApplicationRecord(final EProtocolVersion version) {
        super(EContentType.APPLICATION, version);
    }

    /**
     * {@inheritDoc}
     *
     * AHandshakeRecord representation 1 byte Message type 3 + x bytes Payload
     */
    @Override
    public byte[] encode(final boolean chained) {

        int pointer;
        //byte[] tmp;
        byte[] payloadCopy = getPayload();
        //byte[] applicationRecord = new byte[payloadCopy.length + LENGTH_MAC_FIELD];

        pointer = 0;

        /*
        // 1. payload
        tmp = payloadCopy;
        System.arraycopy(tmp, 0, applicationRecord, pointer, tmp.length);
        pointer += tmp.length;        
        
        // 2. MAC
        SecurityParameters param = SecurityParameters.getInstance();
        KeyMaterial keyMat = new KeyMaterial();
        String macName = param.getMacAlgorithm().toString();
        SecretKey macKey = new SecretKeySpec(keyMat.getClientMACSecret(), macName);
        MACComputation mac = new MACComputation(macKey, "SHA1");
        byte[] payloadLength = new byte[] {
            (byte)((tmp.length + LENGTH_MAC_FIELD) >>> 24),
            (byte)((tmp.length + LENGTH_MAC_FIELD) >>> 16),
            (byte)((tmp.length + LENGTH_MAC_FIELD) >>> 8),
            (byte)(tmp.length + LENGTH_MAC_FIELD)
        };
        tmp = mac.computeMAC(this.getProtocolVersion().getId(), this.getContentType().getId(), payloadLength, payloadCopy);
        System.arraycopy(tmp, 0, applicationRecord, pointer, tmp.length);
        Logger.getRootLogger().debug("Testmessage: " + Utility.bytesToHex(applicationRecord));
        //pointer += tmp.length;
        
        // 3. Padding (TODO)*/

        super.setPayload(payloadCopy);
        return chained ? super.encode(true) : payloadCopy;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        /*
        final byte[] payloadCopy;
        byte[] tmpBytes;
        int pointer;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Application record too short.");
        }

        pointer = 0;

        // 1. payload 
        tmpBytes = new byte[payloadCopy.length - LENGTH_MAC_FIELD];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        setPayload(tmpBytes);
        pointer += tmpBytes.length;
        
        // 2. MAC
        tmpBytes = new byte[LENGTH_MAC_FIELD];
        System.arraycopy(payloadCopy, pointer, tmpBytes, pointer, tmpBytes.length);
        //TODO: Do something with MAC...
        //pointer += tmpBytes.length;
        
        // 3. Padding (TODO)
        */
        super.decode(message, chained);
    }
    
    public String toString() {
    	return super.toString();
    }

}
