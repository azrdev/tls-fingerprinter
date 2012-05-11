package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EHashAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * . * PRF - as defined in RFC-2246
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 1, 2012
 */
public class PseudoRandomFunction {

    public final static int MD5_BLOCK_LENGTH = 16;
    public final static int SHA1_BLOCK_LENGTH = 20;
    private EHashAlgorithm hashAlgorithm = null;
    private Mac hmd5 = null;
    private Mac hsha1 = null;
    private final int length;

    public PseudoRandomFunction(final int length) {
        this.length = length;
        try {
            hmd5 = Mac.getInstance("HmacMD5");
            hsha1 = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public byte[] generatePseudoRandomValue(byte[] secret, String label,
            byte[] seed) throws InvalidKeyException {
        int secret_length = secret.length;
        byte part1[], part2[] = null;
        byte[] md5_part = new byte[length];
        byte[] sha1_part = new byte[length];
        byte[] output = new byte[length];

        //create Hash seed
        byte[] hashSeed = this.createHashSeed(label, seed);

        //PreMasterSecret has to be devided in to parts
        int part_length = Math.round(secret_length / 2);
        byte[] secret1 = new byte[part_length];
        byte[] secret2 = new byte[part_length];
        //copy each part in an extra array
        System.arraycopy(secret, 0, secret1, 0, part_length);
        System.arraycopy(secret, secret_length - part_length, secret2, 0,
                part_length);
        float rounds = 0.0f;
        rounds = (float) length / (float) MD5_BLOCK_LENGTH;
        hashAlgorithm = EHashAlgorithm.MD5;
        //generate two parts using p_hash function
        part1 = p_hash(secret1, hashSeed, (int) Math.ceil(rounds));
        System.arraycopy(part1, 0, md5_part, 0, length);
        rounds = (float) length / (float) SHA1_BLOCK_LENGTH;
        hashAlgorithm = EHashAlgorithm.SHA1;
        part2 = p_hash(secret2, hashSeed, (int) Math.ceil(rounds));
        System.arraycopy(part2, 0, sha1_part, 0, length);
        //XOR the two parts
        for (int i = 0; i < length; i++) {
            output[i] = (byte) (md5_part[i] ^ sha1_part[i]);
        }
        return output;
    }

    private byte[] createHashSeed(String label, byte[] seed) {
        byte[] labelBytes = label.getBytes();
        byte[] hashSeed = new byte[seed.length + labelBytes.length];
        int pointer = 0;
        System.arraycopy(labelBytes, 0, hashSeed, pointer, labelBytes.length);
        pointer += labelBytes.length;
        System.arraycopy(seed, 0, hashSeed, pointer, seed.length);
        return hashSeed;
    }

    /**
     * generates the output of a HMAC_SHA1
     *
     * @param secret Secret key
     * @param seed the seed
     * @return HMAC_SHA1 output
     * @throws InvalidKeyException
     */
    private byte[] p_sha1(final byte[] secret, final byte[] seed) throws
            InvalidKeyException {
        SecretKey key = new SecretKeySpec(secret, "HmacSHA1");
        hsha1.init(key);
        return hsha1.doFinal(seed);
    }

    /**
     * generates the output of a HMAC_MD5
     *
     * @param secret Secret key
     * @param seed the seed
     * @return HMAC_MD5 output
     * @throws InvalidKeyException
     */
    private byte[] p_md5(byte[] secret, byte[] seed) throws InvalidKeyException {
        SecretKey key = new SecretKeySpec(secret, "HmacMD5");
        hmd5.init(key);
        return hmd5.doFinal(seed);
    }

    /**
     * generates the bytes of the p_hash function
     *
     * @param secret
     * @param seed
     * @param rounds Loops to run
     * @return
     * @throws InvalidKeyException
     */
    private byte[] p_hash(byte[] secret, byte[] seed, final int rounds) throws
            InvalidKeyException {
        byte[] a0 = seed;
        byte[] a1 = null;
        byte[] a2 = null;
        byte[] output = null;
        byte[] hmac_hash = null;
        byte[] currentHash = null;
        switch (this.hashAlgorithm) {
            case MD5:
                output = new byte[MD5_BLOCK_LENGTH * rounds];
                a1 = p_md5(secret, a0);
                currentHash = a1;
                break;
            case SHA1:
                output = new byte[SHA1_BLOCK_LENGTH * rounds];
                a1 = p_sha1(secret, a0);
                currentHash = a1;
                break;
            default:
                break;
        }
        int pointer = 0;
        for (int i = 0; i < rounds; i++) {
            //create new seed for the hmac_hash function
            byte[] new_seed = new byte[currentHash.length + seed.length];
            System.arraycopy(currentHash, 0, new_seed, 0, currentHash.length);
            System.arraycopy(seed, 0, new_seed, currentHash.length, seed.length);
            //call hmac_hash function
            switch (this.hashAlgorithm) {
                case MD5:
                    currentHash = p_md5(secret, currentHash);
                    hmac_hash = p_md5(secret, new_seed);
                    break;
                case SHA1:
                    currentHash = p_sha1(secret, currentHash);
                    hmac_hash = p_sha1(secret, new_seed);
                    break;
                default:
                    break;
            }
//			safe the output bytes in an array
            System.arraycopy(hmac_hash, 0, output, pointer, hmac_hash.length);
            pointer += hmac_hash.length;
        }
        //return total output
        return output;
    }
}
