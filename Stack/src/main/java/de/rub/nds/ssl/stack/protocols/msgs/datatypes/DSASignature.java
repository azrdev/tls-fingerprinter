package de.rub.nds.ssl.stack.protocols.msgs.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import java.security.*;

/**
 * DSA signature computations.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de May 17, 2012
 */
public class DSASignature implements ISignature {

    /**
     * Server key exchange parameters.
     */
    private byte[] parameters;

    /**
     * Initialize DSASignature with the key exchange parameters.
     *
     * @param serverParams Server key exchange parameters
     */
    public DSASignature(final byte[] serverParams) {
        this.parameters = serverParams.clone();
    }

    /**
     * Check a DSS signed message. If RSA was used to sign a message, the
     * message is first hashed with SHA1. Afterwards the signature is applied.
     *
     * @param signature Signature bytes
     * @param pk Public key
     * @return True if signature verification was successful
     */
    public final boolean checkSignature(final byte[] signature,
            final PublicKey pk) {
        boolean valid = false;
        SecurityParameters params = SecurityParameters.getInstance();
        byte[] clientRandom = params.getClientRandom();
        byte[] serverRandom = params.getServerRandom();
        Signature sig;
        try {
            sig = Signature.getInstance("SHA1withDSA");
            sig.initVerify(pk);
            sig.update(clientRandom);
            sig.update(serverRandom);
            sig.update(this.parameters);
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
}
