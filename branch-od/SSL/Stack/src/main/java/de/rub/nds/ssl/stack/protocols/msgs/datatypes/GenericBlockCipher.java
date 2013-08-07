package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.ssl.stack.crypto.MACComputation;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/**
 * Block cipher encryption and MAC computation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 21, 2012
 */
public class GenericBlockCipher extends APubliclySerializable implements
        IGenericCipher {

    /**
     * Plain record.
     */
    private ARecordFrame plainRecord = null;
    /**
     * The encrypted record data.
     */
    private byte[] encryptedData = null;
    /**
     * Message in cleartext.
     */
    private byte[] cleartext = null;
    /**
     * The payload MAC.
     */
    private byte[] macData;
    /**
     * Length of the block padding.
     */
    private int paddingLength;
    /**
     * Padding for block cipher encryption.
     */
    private byte[] padding;

    /**
     * Initialize a GenericBlockCipher as defined in RFC2246.
     *
     * @param data Ciphertext
     */
    public GenericBlockCipher(final byte[] data) {
        this.decode(data, false);
    }

    /**
     * Initialize a GenericBlockCipher as defined in RFC2246.
     *
     * @param frame Non-encrypted record frame
     */
    public GenericBlockCipher(final ARecordFrame frame) {
        this.plainRecord = frame;
    }

    /**
     * Concatenate data and MAC, add padding and encrypt data.
     *
     * @param key Symmetric key
     * @param cipherName Name of the symmetric cipher
     * @param iv Initialization vector for ciphertext computation
     */
    public final void encryptData(final SecretKey key,
            String cipherName, final byte[] iv) {
        Cipher blockCipher = null;
        int blockSize = 0;
        try {
            blockCipher = Cipher.getInstance(cipherName + "/CBC/NoPadding");
            AlgorithmParameters params =
                    AlgorithmParameters.getInstance(cipherName);
            IvParameterSpec iVector = new IvParameterSpec(iv);
            params.init(iVector);
            blockCipher.init(Cipher.ENCRYPT_MODE, key, params);
            blockSize = blockCipher.getBlockSize();
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
        int payloadLength = this.plainRecord.getPayload().length;
        // padding precomputation
        // padding length + 1 since we add the paddingLength field
        this.createPadding(payloadLength
                + 1 + macData.length, blockSize);
        byte[] paddedData = getPadding();
        byte[] paddedDataLength = new byte[]{(byte) (paddedData.length)};

        byte[] tmp = new byte[payloadLength + macData.length
                + paddedData.length + paddedDataLength.length];
        // 1. add payload
        System.arraycopy(this.plainRecord.getPayload(),
                0, tmp, pointer, payloadLength);
        pointer += payloadLength;
        // 2. add MAC
        System.arraycopy(macData, 0, tmp, pointer, macData.length);
        pointer += macData.length;
        // 3. add Padding
        System.arraycopy(paddedData, 0, tmp, pointer, paddedData.length);
        pointer += paddedData.length;
        // 4. add padding length
        System.arraycopy(paddedDataLength, 0, tmp, pointer,
                paddedDataLength.length);

        //encrypt the data
        if (blockCipher != null) {
            try {
                encryptedData = blockCipher.doFinal(tmp);
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Decrypt the data of an encrypted data record.
     *
     * @param key Symmetric key
     * @param cipherName Name of the symmetric cipher
     * @param iv Initialization vector for ciphertext computation
     * @return Decrypted data
     */
    public final byte[] decryptData(final SecretKey key,
            final String cipherName, final byte[] iv) {
        Cipher blockCipher;
        try {
            blockCipher = Cipher.getInstance(cipherName + "/CBC/NoPadding");
            AlgorithmParameters params =
                    AlgorithmParameters.getInstance(cipherName);
            IvParameterSpec iVector = new IvParameterSpec(iv);
            params.init(iVector);
            blockCipher.init(Cipher.DECRYPT_MODE, key, params);
            //first decrypt the data
            this.cleartext = blockCipher.doFinal(this.encryptedData);
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
        return cleartext.clone();
    }

    /**
     * Initialize block cipher for ciphertext computation.
     *
     * @param key Symmetric key for encryption
     * @param cipherName Symmetric cipher
     * @param iv Initialization vector
     * @return Cipher object
     */
    public final Cipher initBlockCipher(final SecretKey key,
            final String cipherName, final byte[] iv) {
        Cipher blockCipher = null;
        AlgorithmParameters params = null;

        IvParameterSpec iVector = new IvParameterSpec(iv);
        try {
            blockCipher = Cipher.getInstance(cipherName + "/CBC/NoPadding");
            params = AlgorithmParameters.getInstance(cipherName);
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
        return blockCipher;
    }

    /**
     * Padding as described in Chapter 6.2.3.2 of RFC 2246.
     *
     * @param dataLength Length of the data that should be padded
     * @param blockSize Block size of the cipher
     */
    public final void createPadding(final int dataLength,
            final int blockSize) {
        int padLength = 0;

        if ((dataLength % blockSize) != 0) {
            padLength = blockSize - (dataLength % blockSize);
            setPaddingLength(padLength);
        } else {
            padLength = blockSize;
            setPaddingLength(padLength);
        }
        byte length = (byte) (padLength);
        byte[] tmp = new byte[padLength];
        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = length;
        }
        setPadding(tmp);
    }

    /**
     * Check the padding of a decrypted payload and remove it.
     *
     * @param payload Decrypted payload
     */
    public final void checkAndRemovePadding(final byte[] payload) {
        int payloadLength = payload.length;
        this.paddingLength = extractLength(payload, payloadLength - 1, 1);
        setPaddingLength(paddingLength);
        byte padByteValue = (byte) paddingLength;
        for (int i = payloadLength - paddingLength; i < payloadLength; i++) {
            if (payload[i] != padByteValue) {
                try {
                    throw new Exception("Invalid padding");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        int unpaddedLength = payloadLength - paddingLength;
        byte[] unpaddedData = new byte[unpaddedLength];
        System.arraycopy(payload, 0, unpaddedData, 0, unpaddedLength);
    }

    /**
     * Compute the MAC of the payload.
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
     * Concatenates the record payload and the MAC.
     *
     * @param data Record payload
     * @param mac MAC of the payload
     * @return Concatenated data
     */
    public final byte[] concatenateDataMAC(final byte[] data,
            final byte[] mac) {
        int pointer = 0;
        int payloadLength = data.length;
        byte[] tmp = new byte[mac.length + payloadLength];
        //add payload
        System.arraycopy(data, 0, tmp, pointer, payloadLength);
        pointer += payloadLength;
        //add the MAC
        System.arraycopy(mac, 0, tmp, pointer, mac.length);
        return tmp;
    }

    /**
     * Set padding bytes of a block.
     *
     * @param padString Padding bytes
     */
    public final void setPadding(final byte[] padString) {
        this.padding = padString.clone();
    }

    /**
     * Get padding bytes of a block.
     *
     * @return Padding bytes
     */
    public final byte[] getPadding() {
        return this.padding.clone();
    }

    /**
     * Set the length of the block padding.
     *
     * @param padLength Length of the block padding
     */
    public final void setPaddingLength(final int padLength) {
        this.paddingLength = padLength;
    }

    /**
     * Get the length of the block padding.
     *
     * @return Length of the block padding
     */
    public final int getPaddingLength() {
        return this.paddingLength;
    }

    /**
     * Get the payload MAC.
     *
     * @return The MAC of the payload
     */
    public final byte[] getMAC() {
        return this.macData.clone();
    }

    @Override
    public final void decode(final byte[] message,
            final boolean chained) {
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

    /**
     * Get block-ciphered content.
     *
     * @return Block-ciphered content
     */
    public final byte[] getContent() {
        return this.encryptedData.clone();
    }

    /**
     * Set block-ciphered content.
     *
     * @param encPayload Block-ciphered content
     */
    public final void setContent(final byte[] encPayload) {
        this.encryptedData = encPayload.clone();
    }
}
