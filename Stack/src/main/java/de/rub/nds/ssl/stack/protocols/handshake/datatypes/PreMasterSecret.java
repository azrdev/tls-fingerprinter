package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * PreMasterSecret part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 17, 2012
 */
public final class PreMasterSecret extends APubliclySerializable
        implements IExchangeKeys {

    /**
     * Length of the random value: 46 Bytes.
     */
    private static final int LENGTH_RANDOM = 46;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED =
            EProtocolVersion.LENGTH_ENCODED
            + LENGTH_RANDOM;
    /**
     * Protocol version.
     */
    private EProtocolVersion protocolVersion = null;
    /**
     * Random value.
     */
    private byte[] random = new byte[LENGTH_RANDOM];
    /**
     * Diffie Hellman key.
     */
    private byte[] dhZ;
    /**
     * Elliptic Curve Diffie Hellman key
     */
    private byte[] ecdhKey;

    /**
     * Initializes a PreMasterSecret part as defined in RFC 2246.
     *
     * @param version Protocol version
     */
    public PreMasterSecret(final EProtocolVersion version) {
        this.protocolVersion = EProtocolVersion.valueOf(version.name());
        // initialize random
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(random);
    }

    /**
     * Initializes a PreMasterSecret part as definied in RFC 2246, when Diffie
     * Hellman is used as key exchange algorithm.
     *
     * @param clientYs Client exchange key
     * @param serverYs Server exchange key
     * @param mod Prime modulus
     */
    public PreMasterSecret(final byte[] clientYs,
            final byte[] serverYs, final byte[] mod) {
        BigInteger cYs = new BigInteger(1, clientYs);
        BigInteger sYs = new BigInteger(1, serverYs);
        BigInteger modulus = new BigInteger(1, mod);

        byte[] key = sYs.modPow(cYs, modulus).toByteArray();
        byte[] tmp = new byte[mod.length];
        if (key.length > mod.length) {
            System.arraycopy(key, 1, tmp, 0, mod.length);
            key = tmp.clone();
        }
        this.setDHKey(key);
    }

    /**
     * Initializes a PreMasterSecret part as defined in RFC 2246.
     *
     * @param message PreMasterSecret part in encoded form
     */
    public PreMasterSecret(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * TODO
     * temporary code from sun/security/ssl/ECDHCrypt.java
     * 
     * @param peerPublicKey 
     */
//    public PreMasterSecret(PublicKey peerPublicKey) {
//        try {
//            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
//            ka.init(privateKey);
//            ka.doPhase(peerPublicKey, true);
//            this.setEcdhKey(ka.generateSecret("TlsPremasterSecret").getEncoded());
//        } catch (GeneralSecurityException e) {
//            throw new RuntimeException("Could not generate secret", e);
//        }
//    }

    /**
     * Get the protocol version.
     *
     * @return The protocol version of this message part.
     */
    public EProtocolVersion getProtocolVersion() {
        // deep copy
        return EProtocolVersion.valueOf(this.protocolVersion.name());
    }

    /**
     * Set the protocol version of this message part.
     *
     * @param version The protocol version to be used
     */
    public void setProtocolVersion(
            final EProtocolVersion version) {
        if (this.protocolVersion == null) {
            throw new IllegalArgumentException(
                    "Protocol version must not be null!");
        }

        this.protocolVersion = EProtocolVersion.valueOf(
                version.name());
    }

    /**
     * Set the protocol version of this message.
     *
     * @param version The protocol version object to be used for in encoded form
     */
    public void setProtocolVersion(final byte[] version) {
        this.protocolVersion = EProtocolVersion.getProtocolVersion(
                version);
    }

    /**
     * Get the random of this message.
     *
     * @return The random of this message
     */
    public byte[] getRandom() {
        // deep copy
        byte[] copy = new byte[LENGTH_RANDOM];
        System.arraycopy(random, 0, copy, 0, LENGTH_RANDOM);
        return copy;
    }

    /**
     * Set the random of this message part.
     *
     * @param randomBytes The random bytes of this message part
     */
    public void setRandom(final byte[] randomBytes) {
        if (randomBytes == null
                || randomBytes.length != LENGTH_RANDOM) {
            throw new IllegalArgumentException("Random bytes"
                    + "must not be exactly " + LENGTH_RANDOM + " bytes!");
        }
        // deep copy
        System.arraycopy(randomBytes, 0, random, 0, randomBytes.length);
    }

    /**
     * Get the generated DH key.
     *
     * @return DH key
     */
    public byte[] getDHKey() {
        return dhZ.clone();
    }

    /**
     * Set the generated DH key.
     *
     * @param key DH key
     */
    public void setDHKey(final byte[] key) {
        this.dhZ = key.clone();
    }

    /**
     * Get generated ECDH key
     *
     * @return ECDH key
     */
    public byte[] getEcdhKey() {
        return ecdhKey.clone();
    }

    /**
     * Set generated ECDH key
     *
     * @param ecdhKey ECDH key
     */
    public void setEcdhKey(byte[] ecdhKey) {
        this.ecdhKey = ecdhKey.clone();
    }

    /**
     * {@inheritDoc}
     *
     * PreMasterSecret representation 2 bytes Protocol version 48 bytes Random
     * value.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        byte[] tmp;

        // putting the pieces together
        byte[] preMasterSecret = new byte[LENGTH_MINIMUM_ENCODED];

        /*
         * Prepare PreMasterSecret part
         */
        // 1. add protocol version
        tmp = this.getProtocolVersion().getId();
        System.arraycopy(tmp, 0, preMasterSecret, pointer, tmp.length);
        pointer += tmp.length;

        // 2. add random part
        System.arraycopy(random, 0, preMasterSecret, pointer, random.length);
        //pointer += random.length;

        return preMasterSecret;
    }

    /**
     * {@inheritDoc}
     */
    public void decode(final byte[] message, final boolean chained) {
        final byte[] secret = new byte[message.length];
        byte[] tmpBytes;
        int pointer;

        // deep copy
        System.arraycopy(message, 0, secret, 0, secret.length);

        // check size
        if (secret.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("PreMasterSecret too short.");
        } else if (secret.length > LENGTH_MINIMUM_ENCODED) {
            System.err.println(Arrays.toString(secret));
            throw new IllegalArgumentException("PreMasterSecret too long: "
                    + secret.length + " > " + LENGTH_MINIMUM_ENCODED);
        }

        pointer = 0;
        // 1. extract protocol version
        tmpBytes = new byte[EProtocolVersion.LENGTH_ENCODED];
        System.arraycopy(secret, pointer, tmpBytes, 0, tmpBytes.length);
        setProtocolVersion(tmpBytes);
        pointer += tmpBytes.length;

        // 2. extract random value
        tmpBytes = new byte[LENGTH_RANDOM];
        System.arraycopy(secret, pointer, tmpBytes, 0, tmpBytes.length);
        setRandom(tmpBytes);
        //pointer += tmpBytes.length;
    }
}
