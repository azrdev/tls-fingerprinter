package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;

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
        ISignature sign;
        if (this.sigAlgorithm == ESignatureAlgorithm.RSA) {
            sign = new RSASignature(getServerParams());
            valid = sign.checkSignature(signature, keyParams.getPublicKey());
        } else {
            sign = new DSASignature(getServerParams());
            valid = sign.checkSignature(signature, keyParams.getPublicKey());
        }
        return valid;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] encode(final boolean chained) {
        /*
         * To be implemented.
         */
        byte[] tmp = new byte[0];
        return tmp;
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
        return sigValue.clone();
    }

    /**
     * Set the signature value.
     *
     * @param value Signature value
     */
    public final void setSignatureValue(final byte[] value) {
        this.sigValue = value.clone();
    }
}
