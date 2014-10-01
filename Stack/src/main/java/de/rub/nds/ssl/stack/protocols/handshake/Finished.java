package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.PseudoRandomFunction;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EMessageType;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import java.security.InvalidKeyException;

/**
 * Defines the Finished message of SSL/TLS as defined in RFC 2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Feb 16, 2012
 */
public final class Finished extends AHandshakeRecord {

    /**
     * Length of the verify data
     */
    private static final int VERIFY_DATA_LENGTH = 12;
    /**
     * Verify Data of the finished message
     */
    private byte[] verifyData = null;
    private String label;

    /**
     * Initializes a Finished message as defined in RFC 2246.
     *
     * @param message Finished message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public Finished(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.setMessageType(EMessageType.FINISHED);
        this.decode(message, chained);
    }

    /**
     * Initializes a Finished message as defined in RFC 2246.
     *
     * @param protocolVersion Protocol version of this message
     */
    public Finished(final EProtocolVersion protocolVersion,
            final EConnectionEnd endpoint) {
        super(protocolVersion, EMessageType.FINISHED);
        verifyData = new byte[VERIFY_DATA_LENGTH];
        if (endpoint == EConnectionEnd.CLIENT) {
            label = "client finished";
        } else {
            label = "server finished";
        }
    }

    /**
     * Creates the verify data bytes of the finished message
     *
     * @param secret Master secret
     * @param handshakeHashes concatenated hashes of the handshake messages
     * @throws InvalidKeyException
     */
    public void createVerifyData(final MasterSecret secret,
            final byte[] handshakeHashes) throws InvalidKeyException {
        PseudoRandomFunction prf = new PseudoRandomFunction(VERIFY_DATA_LENGTH);
        verifyData = prf.generatePseudoRandomValue(secret.getMasterSecret(),
                label, handshakeHashes.clone());
    }

    /**
     * {@inheritDoc}
     *
     * Finished representation 12 bytes verify data
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] data = new byte[VERIFY_DATA_LENGTH];
        System.arraycopy(verifyData, 0, data, 0, VERIFY_DATA_LENGTH);
        super.setPayload(data);
        return chained ? super.encode(false) : data;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] tmpBytes;
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        // check size
        if (payloadCopy.length < VERIFY_DATA_LENGTH) {
            throw new IllegalArgumentException("Finished message too short.");
        }

        // 1. extract verify data 
        tmpBytes = new byte[VERIFY_DATA_LENGTH];
        System.arraycopy(payloadCopy, 0, tmpBytes, 0, tmpBytes.length);
        setVerifyData(tmpBytes);

    }

    /**
     * Set the verify data of the finished message.
     *
     * @param verifyData Verify Data of a finished message
     */
    public void setVerifyData(final byte[] verifyData) {
        this.verifyData = verifyData.clone();
    }

    /**
     * Get the verify data of the finished message.
     *
     * @return 12 Bytes verify Data of a finished message
     */
    public byte[] getVerifyData() {
        return this.verifyData.clone();
    }
}
