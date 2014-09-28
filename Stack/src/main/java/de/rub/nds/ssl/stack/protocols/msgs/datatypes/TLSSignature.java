package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.ssl.stack.exceptions.SignatureInvalidException;
import de.rub.nds.ssl.stack.exceptions.UnknownHashAlgorithmException;
import de.rub.nds.ssl.stack.exceptions.UnknownSignatureAlgorithmException;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.SignatureAndHashAlgorithm;

import java.util.Arrays;

/**
 * TLS signature as defined in RFC 2246. The signature algorithms DSA and RSA
 * are supported.
 *
 * TODO: rework this whole class :-/
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
     * @param encodedSignature The Signature in encoded form
     * @param message The bytes the signature is calculated for
     */
    public TLSSignature(final byte[] encodedSignature, final byte[] message) {
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        this.sigAlgorithm = keyParams.getSignatureAlgorithm();

        this.setServerParams(message);
        this.decode(encodedSignature, false);
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
        ISignature sign;

        if(sigAlgorithm == null)
            throw new IllegalArgumentException(
                    "Cannot check signature: SignatureAlgorithm null");

        switch(sigAlgorithm) {
            case RSA:
                sign = new RSASignature(getServerParams());
                return sign.checkSignature(signature, keyParams.getPublicKey());
            case DSS:
                sign = new DSASignature(getServerParams());
                return sign.checkSignature(signature, keyParams.getPublicKey());
            default:
                throw new IllegalArgumentException(
                        "Signature check not implemented for " + sigAlgorithm);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] encode(final boolean chained) {
        //TODO: implement TLSSignature.encode()
        return new byte[0];
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        int sigLength = 0;
        byte[] tmpBytes;
        int pointer = 0;

        // deep copy
        final byte[] paramCopy = new byte[message.length];
        System.arraycopy(message, 0, paramCopy, 0, paramCopy.length);

        /*TODO: get protocol version to decide if signature contains
        SignatureAndHashAlgorithm

        if(sigAlgorithm == null) {
            // TLS >= 1.2 contains a SignatureAndHashAlgorithm spec in the signature
            if(paramCopy.length >= SignatureAndHashAlgorithm.LENGTH_ENCODED) {
                byte[] tmp = Arrays.copyOfRange(paramCopy, 0,
                        SignatureAndHashAlgorithm.LENGTH_ENCODED);
                try {
                    SignatureAndHashAlgorithm algorithms = new SignatureAndHashAlgorithm(tmp);

                    this.sigAlgorithm = algorithms.getSignatureAlgorithm();
                    pointer += SignatureAndHashAlgorithm.LENGTH_ENCODED;
                } catch(UnknownSignatureAlgorithmException |
                        UnknownHashAlgorithmException ex) {
                    // either unimplemented or protocol version < 1.2 => no algorithm fields
                }
            }
        }
        */

        if(sigAlgorithm == null)
            throw new IllegalStateException("Could not determine SignatureAlgorithm");

        switch(sigAlgorithm) {
            case anon:
                /*
                 * if signature algorithm is set to "anonymous" no signature value
                 * was added
                 */
                setSignatureValue(new byte[0]);
                break;

            case RSA:
            case DSS:
                if(pointer + LENGTH_LENGTH_FIELD > paramCopy.length)
                    throw new IllegalArgumentException("Signature too short");

                // extract signature length
                sigLength = extractLength(paramCopy, pointer, LENGTH_LENGTH_FIELD);
                pointer += LENGTH_LENGTH_FIELD;
                if(pointer + sigLength > paramCopy.length)
                    throw new IllegalArgumentException("Signature length field invalid");

                // extract signature
                tmpBytes = new byte[sigLength];
                System.arraycopy(paramCopy, pointer, tmpBytes, 0, tmpBytes.length);
                setSignatureValue(tmpBytes);

                if (!(checkSignature(getSignatureValue()))) {
                    throw new SignatureInvalidException();
                }

                break;

            case ECDSA:

            default:
                throw new IllegalArgumentException(
                        "Signature not implemented for " + sigAlgorithm);
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
