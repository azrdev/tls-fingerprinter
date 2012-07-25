package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;

/**
 * RSA signature computations.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de May 17, 2012
 */
public class RSASignature implements ISignature {

    /**
     * Length of a SHA1 hash.
     */
    private static final int SHA1_LENGTH = 20;
    /**
     * Length of a MD5 hash.
     */
    private static final int MD5_LENGTH = 16;
    /**
     * Length of concatenated MD5 and SHA1 hash.
     */
    private static final int CONCAT_HASH_LENGTH = SHA1_LENGTH + MD5_LENGTH;
    /**
     * Server key exchange parameters.
     */
    private byte[] parameters;

    /**
     * Initialize RSASignature with the key exchange parameters.
     *
     * @param serverParams Server key exchange parameters
     */
    public RSASignature(final byte[] serverParams) {
        this.parameters = serverParams.clone();
    }

    /**
     * Check a RSA signed message. If RSA was used to sign a message, the
     * message is first hashed with MD5 and SHA1. Afterwards the signature is
     * applied
     *
     * @param signature Signature bytes
     * @param pk Public key
     * @return True if signature verification was successful
     */
    public final boolean checkSignature(final byte[] signature,
            final PublicKey pk) {
        SecurityParameters params = SecurityParameters.getInstance();
        byte[] clientRandom = params.getClientRandom();
        byte[] serverRandom = params.getServerRandom();
        byte[] md5Hash;
        byte[] sha1Hash;
        byte[] concat = new byte[CONCAT_HASH_LENGTH];
        md5Hash = md5Hash(clientRandom, serverRandom,
                this.parameters);
        sha1Hash = sha1Hash(clientRandom, serverRandom,
                this.parameters);
        //concatenate the two hashes
        int pointer = 0;
        System.arraycopy(md5Hash, 0, concat, pointer, md5Hash.length);
        pointer += md5Hash.length;
        System.arraycopy(sha1Hash, 0, concat, pointer, sha1Hash.length);
        //compute signature
        byte[] msg = null;
        if (pk != null && pk instanceof RSAPublicKey) {
            RSAPublicKey rsaPK = (RSAPublicKey) pk;
            msg = RsaUtil.pubOp(signature, rsaPK);
        }
        byte[] recHash = new byte[CONCAT_HASH_LENGTH];
        if (msg != null) {
            System.arraycopy(msg, msg.length - recHash.length, recHash, 0,
                    recHash.length);
        }
        return Arrays.equals(recHash, concat);
    }

    /**
     * Generate a MD5 Hash for the signature.
     *
     * @param clientRandom Client random parameter
     * @param serverRandom Server random parameter
     * @param params Server parameters
     * @return MD5 hash
     */
    public final byte[] md5Hash(final byte[] clientRandom,
            final byte[] serverRandom, final byte[] params) {
        byte[] result = null;
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
            md5.update(clientRandom);
            md5.update(serverRandom);
            md5.update(params);
            result = md5.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Generate a SHA1 Hash for the signature.
     *
     * @param clientRandom Client random parameter
     * @param serverRandom Server random parameter
     * @param params Server parameters
     * @return SHA1 hash
     */
    public final byte[] sha1Hash(final byte[] clientRandom,
            final byte[] serverRandom, final byte[] params) {
        byte[] result = null;
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA");
            sha1.update(clientRandom);
            sha1.update(serverRandom);
            sha1.update(params);
            result = sha1.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }
}
