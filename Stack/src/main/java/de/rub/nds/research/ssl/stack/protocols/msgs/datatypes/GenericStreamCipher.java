package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.research.ssl.stack.crypto.MACComputation;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;

/**
 * Stream cipher encryption/decrpytion and MAC computation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 01, 2012
 *
 */
public class GenericStreamCipher extends APubliclySerializable implements
        IGenericCipher {

    /**
     * Plain record.
     */
    private ARecordFrame plainRecord;
    /**
     * The payload MAC.
     */
    private byte[] macData;
    /**
     * The encrypted record data.
     */
    private byte[] encryptedData;

    /**
     * Initialize a GenericStreamCipher as defined in RFC2246
     *
     * @param data Ciphertext
     */
    public GenericStreamCipher(final byte[] data) {
        this.decode(data, false);
    }

    /**
     * Initialize a GenericStreamCipher as defined in RFC2246
     *
     * @param frame Non-encrypted record frame
     */
    public GenericStreamCipher(final ARecordFrame frame) {
        this.plainRecord = frame;
    }

    /**
     * Concatenate data and MAC, encrypt data
     *
     * @param key Symmetric key
     * @param cipherName Name of the symmetric cipher
     */
    public final void encryptData(final SecretKey key,
            final String cipherName) {
        Cipher streamCipher = null;
        int pointer = 0;
        int payloadLength = 0;
        try {
            streamCipher =
                    Cipher.getInstance(cipherName);
            streamCipher.init(Cipher.ENCRYPT_MODE, key);

            //concatenate data and MAC
            if (this.plainRecord != null
                    && this.plainRecord.getPayload() != null) {
                payloadLength = this.plainRecord.getPayload().length;

                byte[] tmp = new byte[macData.length + payloadLength];
                System.arraycopy(this.plainRecord.getPayload(),
                        0, tmp, pointer, payloadLength);
                pointer += payloadLength;

                System.arraycopy(macData, 0, tmp, pointer, macData.length);

                encryptedData = streamCipher.doFinal(tmp);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Compute the MAC of the payload
     *
     * @param key Secret key for MAC computation
     * @param macName MAC algorithm
     */
    public final void computePayloadMAC(final SecretKey key,
            final String macName) {
        byte[] payload = this.plainRecord.getPayload();
        byte[] protocolVersion =
                this.plainRecord.getProtocolVersion().getId();
        byte contentType = this.plainRecord.getContentType().getId();
        byte[] payloadLength = super.buildLength(payload.length, 2);
        MACComputation comp = new MACComputation(key, macName);
        this.macData = comp.computeMAC(protocolVersion,
                contentType, payloadLength, payload);
    }

    /**
     * Get stream-ciphered content.
     *
     * @return Stream-ciphered content
     */
    public final byte[] getContent() {
        return this.encryptedData;
    }

    /**
     * Set stream-ciphered content.
     *
     * @param encPayload Stream-ciphered content
     */
    public final void setContent(final byte[] encPayload) {
        this.encryptedData = encPayload;
    }

    @Override
    public final void decode(final byte[] message, final boolean chained) {
        final byte[] encPayload = new byte[message.length];
        // deep copy
        System.arraycopy(message, 0, encPayload, 0, encPayload.length);
        setContent(encPayload);
    }

    @Override
    public final byte[] encode(final boolean chained) {
        byte[] encryptedPayload = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0,
                encryptedPayload, 0, encryptedData.length);
        return encryptedPayload;
    }
}
