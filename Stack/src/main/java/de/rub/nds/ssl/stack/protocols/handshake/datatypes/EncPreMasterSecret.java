package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * EncPreMasterSecret part - as defined in RFC-2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 *
 * Feb 22, 2012
 */
public final class EncPreMasterSecret extends APubliclySerializable
        implements IExchangeKeys {

    /**
     * Encrypted payload.
     */
    private byte[] ciphertext;
    /**
     * Length bytes.
     */
    public static final int LENGTH_BYTES = 2;

    /**
     * Initializes an EncPreMasterSecret part as defined in RFC 2246.
     *
     * @param pms PreMasterSecret in encoded form
     * @param pk PublicKey
     */
    public EncPreMasterSecret(final byte[] pms, final PublicKey pk) {
        if (pk == null) {
            throw new IllegalArgumentException("Public Key must not be null");
        }
        BigInteger mod = null;
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsaPK = (RSAPublicKey) pk;
            mod = rsaPK.getModulus();
        }
        if (mod == null) {
            throw new IllegalArgumentException("Modulus must not be null");
        }
        int length = mod.bitLength() / Utility.BITS_IN_BYTE;
        this.ciphertext = new byte[length];
        this.encryptPreMasterSecret(pms, pk);
    }

    /**
     * Initializes an EncPreMasterSecret object, PreMasterSecret is not
     * encrypted yet.
     *
     * @param pk PublicKey
     */
    public EncPreMasterSecret(final PublicKey pk) {
        if (pk == null) {
            throw new IllegalArgumentException("Public Key must not be null");
        }
        BigInteger mod = null;
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsaPK = (RSAPublicKey) pk;
            mod = rsaPK.getModulus();
        }
        if (mod == null) {
            throw new IllegalArgumentException("Modulus must not be null");
        }
        int length = mod.bitLength() / Utility.BITS_IN_BYTE;
        this.ciphertext = new byte[length];
    }

    /**
     * Initializes an EncPreMasterSecret part as defined in RFC 2246.
     *
     * @param message EncPreMasterSecret part in encoded form
     */
    public EncPreMasterSecret(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Encrypts the PreMasterSecret with the extracted PublicKey.
     *
     * @param pms PreMasterSecret to be encrypted
     * @param pk PublicKey for encryption
     * @return encrypted PreMasterSecret
     */
    public byte[] encryptPreMasterSecret(final byte[] pms, final PublicKey pk) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            ciphertext = cipher.doFinal(pms);
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
        }
        return ciphertext.clone();
    }

    /**
     * {@inheritDoc}
     *
     * EncPreMasterSecret 2 length bytes and ciphertext.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        byte[] length = buildLength(ciphertext.length, LENGTH_BYTES);

        byte[] encryptedPreMasterSecret = new byte[LENGTH_BYTES
                + ciphertext.length];

        // 1. add length bytes
        System.arraycopy(length, 0, encryptedPreMasterSecret, pointer,
                length.length);
        pointer += length.length;
        // 2. add ciphertext bytes
        System.arraycopy(ciphertext, 0, encryptedPreMasterSecret, pointer,
                ciphertext.length);

        return encryptedPreMasterSecret;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        final byte[] encryptedSecret = new byte[message.length];
        byte[] tmpBytes;
        int pointer;
        int length;

        // deep copy
        System.arraycopy(message, 0, encryptedSecret,
                0, encryptedSecret.length);

        pointer = 0;
        // 1. extract length
        tmpBytes = new byte[LENGTH_BYTES];
        System.arraycopy(encryptedSecret, pointer,
                tmpBytes, 0, tmpBytes.length);
        pointer += tmpBytes.length;

        // 2. extract ciphertext
        length = extractLength(encryptedSecret, 0, 2);
        tmpBytes = new byte[length];
        System.arraycopy(encryptedSecret, pointer, tmpBytes, 0, length);
        setEncryptedPreMasterSecret(tmpBytes);

    }

    /**
     * Set the encrypted pre_master_secret.
     *
     * @param encPMS Encrypted pre_master_secret
     */
    public void setEncryptedPreMasterSecret(final byte[] encPMS) {
        this.ciphertext = new byte[encPMS.length];
        System.arraycopy(encPMS, 0, ciphertext, 0, encPMS.length);
    }
}
