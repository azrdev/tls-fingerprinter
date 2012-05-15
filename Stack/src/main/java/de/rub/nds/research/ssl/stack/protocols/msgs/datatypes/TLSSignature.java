package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.research.ssl.stack.protocols.handshake.
datatypes.ESignatureAlgorithm;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * TLS signature as defined in RFC 2246. The signature algorithms DSA and RSA
 * are supported.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 03, 2012
 */
public class TLSSignature extends APubliclySerializable {

    /**
     * Signature algorithm of this handshake.
     */
    private ESignatureAlgorithm sigAlgorithm;
    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Servers key exchange parameters.
     */
    private byte[] serverParams;
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
     * Max. count of parameters in ServerKeyExchange message.
     */
    private static final int MAX_COUNT_PARAM = 4;

    /**
     * Signature value.
     */
    private byte[] sigValue = null;

    /**
     * Initialize a TLS signature as defined in RFC 2246.
     *
     * @param algorithm Signature algorithm
     */
    public TLSSignature(final ESignatureAlgorithm algorithm) {
        this.sigAlgorithm = algorithm;
    }

    /**
     * Initialize a TLS signature as defined in RFC 2246.
     *
     * @param message Handshake message bytes
     */
    public TLSSignature(final byte[] message) {
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        this.sigAlgorithm = keyParams.getSignatureAlgorithm();
        this.decode(message, false);
    }

    /**
     * Check the signature of the passed key exchange parameters. Signature
     * checking for RSA and DSA is supported. If RSA is used signature was built
     * over concatenated MD5 and SHA1 hashes.
     *
     * @param signature Signed server key exchange parameters
     * @return True if signature was successfully verified
     */
    public final boolean checkSignature(final byte[] signature) {
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        boolean valid = false;
        if (this.sigAlgorithm == ESignatureAlgorithm.RSA) {
            valid = checkRSASignature(signature, keyParams.getPublicKey());
        } else {
            valid = checkDSSSignature(signature, keyParams.getPublicKey());
        }
        return valid;
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
    public final boolean checkRSASignature(final byte[] signature,
            final PublicKey pk) {
        SecurityParameters params = SecurityParameters.getInstance();
        byte[] clientRandom = params.getClientRandom();
        byte[] serverRandom = params.getServerRandom();
        byte[] parameters = getServerParams();
        byte[] md5Hash;
        byte[] sha1Hash;
        byte[] concat = new byte[CONCAT_HASH_LENGTH];
        md5Hash = md5Hash(clientRandom, serverRandom,
                parameters);
        sha1Hash = sha1Hash(clientRandom, serverRandom,
                parameters);
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
     * Check a DSS signed message. If RSA was used to sign a message, the
     * message is first hashed with SHA1. Afterwards the signature is applied.
     *
     * @param signature Signature bytes
     * @param pk Public key
     * @return True if signature verification was successful
     */
    public final boolean checkDSSSignature(final byte[] signature,
            final PublicKey pk) {
        boolean valid = false;
        SecurityParameters params = SecurityParameters.getInstance();
        byte[] clientRandom = params.getClientRandom();
        byte[] serverRandom = params.getServerRandom();
        byte[] parameters = getServerParams();
        Signature sig;
        try {
            sig = Signature.getInstance("SHA1withDSA");
            sig.initVerify(pk);
            sig.update(clientRandom);
            sig.update(serverRandom);
            sig.update(parameters);
            valid = sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return valid;
    }

    /**
     * Generate a MD5 Hash for the signature.
     *
     * @param clientRandom Client random parameter
     * @param serverRandom Server random parameter
     * @param parameters Server parameters
     * @return MD5 hash
     */
    public final byte[] md5Hash(final byte[] clientRandom,
            final byte[] serverRandom, final byte[] parameters) {
        byte[] result = null;
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
            md5.update(clientRandom);
            md5.update(serverRandom);
            md5.update(parameters);
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
     * @param parameters Server parameters
     * @return SHA1 hash
     */
    public final byte[] sha1Hash(final byte[] clientRandom,
            final byte[] serverRandom, final byte[] parameters) {
        byte[] result = null;
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA");
            sha1.update(clientRandom);
            sha1.update(serverRandom);
            sha1.update(parameters);
            result = sha1.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] encode(final boolean chained) {
        /*
         * To be implemented.
         */
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        int extractedLength;
        int sigLength = 0;
        byte[] tmpBytes;
        // deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);

        if (sigAlgorithm == ESignatureAlgorithm.anon) {
            /*
             * if signature algorithm is set to "anonymous" no signature value
             * was added
             */
            setSignatureValue(new byte[0]);
        } else {
            int pointer = 0;
            for (int i = 0; i < MAX_COUNT_PARAM; i++) {
                extractedLength = extractLength(paramCopy, pointer,
                        LENGTH_LENGTH_FIELD);
                pointer += LENGTH_LENGTH_FIELD + extractedLength;
                if (pointer == paramCopy.length) {
                    sigLength = extractedLength;
                    pointer -= extractedLength;
                    break;
                }
            }
            // extract signature
            tmpBytes = new byte[sigLength];
            System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
            setSignatureValue(tmpBytes);
            //extract serverParams
            byte[] parameters = new byte[paramCopy.length - (sigLength + 2)];
            System.arraycopy(paramCopy, 0, parameters, 0,
                    paramCopy.length - (sigLength + 2));
            setServerParams(parameters);
            if (!(checkSignature(tmpBytes))) {
                try {
                    throw new Exception("Signature invalid");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Get the transmitted server parameters.
     *
     * @return Server parameters
     */
    private byte[] getServerParams() {
        return serverParams;
    }

    /**
     * Set the server parameters.
     *
     * @param parameters Server parameters
     */
    private void setServerParams(final byte[] parameters) {
        this.serverParams = parameters;
    }

    /**
     * Get the signature value.
     *
     * @return Signature value
     */
    public final byte[] getSignatureValue() {
        return sigValue;
    }

    /**
     * Set the signature value.
     * @param value Signature value
     */
    public final void setSignatureValue(final byte[] value) {
        this.sigValue = value;
    }
}
