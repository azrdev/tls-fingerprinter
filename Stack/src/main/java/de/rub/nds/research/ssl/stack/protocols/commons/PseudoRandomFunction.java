package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.
datatypes.EHashAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * PRF - as defined in RFC-2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 1, 2012
 */
public class PseudoRandomFunction {

    /**
     * Length of a MD5 hash value.
     */
    public static final int MD5_BLOCK_LENGTH = 16;
    /**
     * Length of a SHA1 hash value.
     */
    public static final int SHA1_BLOCK_LENGTH = 20;
    /**
     * Hash algorithm.
     */
    private EHashAlgorithm hashAlgorithm = null;
    /**
     * MAC algorithm.
     */
    private Mac hmd5 = null;
    /**
     * MAC algorithm.
     */
    private Mac hsha1 = null;
    /**
     * Length of the secret.
     */
    private final int length;

    /**
     * Initializes the PseudoRandomFunction and creates
     * instances of the MAC algorithms.
     * @param valueLength Length of the pseudo random value
     */
    public PseudoRandomFunction(final int valueLength) {
        this.length = valueLength;
        try {
            hmd5 = Mac.getInstance("HmacMD5");
            hsha1 = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Performs the pseudo random computation.
     * @param secret Secret input
     * @param label Specific label
     * @param seed Seed
     * @return Pseudo random value
     * @throws InvalidKeyException Passed key is invalid
     */
    public final byte[] generatePseudoRandomValue(final byte[] secret,
                    final String label, final byte[] seed)
                    throws InvalidKeyException {
        int secretLength = secret.length;
        byte[] part1, part2 = null;
        byte[] md5Part = new byte[length];
        byte[] sha1Part = new byte[length];
        byte[] output = new byte[length];

        //create Hash seed
        byte[] hashSeed = this.createHashSeed(label, seed);

        //PreMasterSecret has to be devided in to parts
        int partLength = Math.round(secretLength / 2);
        byte[] secret1 = new byte[partLength];
        byte[] secret2 = new byte[partLength];
        //copy each part in an extra array
        System.arraycopy(secret, 0, secret1, 0, partLength);
        System.arraycopy(secret, secretLength - partLength, secret2, 0,
                partLength);
        float rounds = 0.0f;
        rounds = (float) length / (float) MD5_BLOCK_LENGTH;
        hashAlgorithm = EHashAlgorithm.MD5;
        //generate two parts using p_hash function
        part1 = pHash(secret1, hashSeed, (int) Math.ceil(rounds));
        System.arraycopy(part1, 0, md5Part, 0, length);
        rounds = (float) length / (float) SHA1_BLOCK_LENGTH;
        hashAlgorithm = EHashAlgorithm.SHA1;
        part2 = pHash(secret2, hashSeed, (int) Math.ceil(rounds));
        System.arraycopy(part2, 0, sha1Part, 0, length);
        //XOR the two parts
        for (int i = 0; i < length; i++) {
            output[i] = (byte) (md5Part[i] ^ sha1Part[i]);
        }
        return output;
    }

    /**
     * Creates the seed for the p_hash function which is a
     * concatenation of the seed value and the label.
     * @param label Specific label
     * @param seed Seed value
     * @return Hash seed
     */
    private byte[] createHashSeed(final String label,
             final byte[] seed) {
        byte[] labelBytes = label.getBytes();
        byte[] hashSeed = new byte[seed.length + labelBytes.length];
        int pointer = 0;
        System.arraycopy(labelBytes, 0, hashSeed, pointer, labelBytes.length);
        pointer += labelBytes.length;
        System.arraycopy(seed, 0, hashSeed, pointer, seed.length);
        return hashSeed;
    }

    /**
     * Generates the output of a HMAC_SHA1.
     * @param secret Secret key
     * @param seed The seed
     * @return HMAC_SHA1 output
     * @throws InvalidKeyException Passed key is invalid
     */
    private byte[] pSHA1(final byte[] secret,
             final byte[] seed) throws InvalidKeyException {
        SecretKey key = new SecretKeySpec(secret, "HmacSHA1");
        hsha1.init(key);
        return hsha1.doFinal(seed);
    }

    /**
     * Generates the output of a HMAC_MD5.
     * @param secret Secret key
     * @param seed the seed
     * @return HMAC_MD5 output
     * @throws InvalidKeyException Passed key is invalid
     */
    private byte[] pMD5(final byte[] secret,
             final byte[] seed) throws InvalidKeyException {
        SecretKey key = new SecretKeySpec(secret, "HmacMD5");
        hmd5.init(key);
        return hmd5.doFinal(seed);
    }

    /**
     * Generates the bytes of the p_hash function.
     * @param secret Secret input
     * @param seed Seed
     * @param rounds Loops to run
     * @return Computed p_hash output
     * @throws InvalidKeyException Passed key is invalid
     */
    private byte[] pHash(final byte[] secret,
            final byte[] seed, final int rounds)
            throws InvalidKeyException {
        byte[] a0 = seed;
        byte[] a1 = null;
        byte[] output = null;
        byte[] hmacHash = null;
        byte[] currentHash = null;
        switch (this.hashAlgorithm) {
            case MD5:
                output = new byte[MD5_BLOCK_LENGTH * rounds];
                a1 = pMD5(secret, a0);
                currentHash = a1;
                break;
            case SHA1:
                output = new byte[SHA1_BLOCK_LENGTH * rounds];
                a1 = pSHA1(secret, a0);
                currentHash = a1;
                break;
            default:
                break;
        }
        int pointer = 0;
        for (int i = 0; i < rounds; i++) {
            //create new seed for the hmac_hash function
            byte[] newSeed = new byte[currentHash.length + seed.length];
            System.arraycopy(currentHash, 0, newSeed, 0, currentHash.length);
            System.arraycopy(seed, 0, newSeed,
                   currentHash.length, seed.length);
            //call hmac_hash function
            switch (this.hashAlgorithm) {
                case MD5:
                    currentHash = pMD5(secret, currentHash);
                    hmacHash = pMD5(secret, newSeed);
                    break;
                case SHA1:
                    currentHash = pSHA1(secret, currentHash);
                    hmacHash = pSHA1(secret, newSeed);
                    break;
                default:
                    break;
            }
//          safe the output bytes in an array
            System.arraycopy(hmacHash, 0, output, pointer, hmacHash.length);
            pointer += hmacHash.length;
        }
        //return total output
        return output;
    }
}
