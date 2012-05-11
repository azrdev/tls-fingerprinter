package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;
import java.security.PublicKey;

/**
 * A singleton to save data like the key exchange algorithm or the public key
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 26, 2012
 */
public class KeyExchangeParams {

    private static volatile KeyExchangeParams keyExParam = null;
    private PublicKey pk = null;
    private EKeyExchangeAlgorithm algorithm;
    private ESignatureAlgorithm sigAlg;
    private byte[] dhGen;
    private byte[] dhPrime;
    private byte[] dhPublic;

    /**
     * Private constructor for singleton.
     */
    private KeyExchangeParams() {
    }

    /**
     * Public method to create instance.
     *
     * @return Instance of KeyExchangeParam
     */
    public static KeyExchangeParams getInstance() {
        if (keyExParam == null) {
            keyExParam = new KeyExchangeParams();
        }
        return keyExParam;
    }

    public void setPublicKey(final PublicKey pk) {
        this.pk = pk;
    }

    /**
     * Get the PublicKey which was extracted from the Certificate.
     *
     * @return PublicKey
     */
    public PublicKey getPublicKey() {
        return this.pk;
    }

    public void setKeyExchangeAlgorithm(final EKeyExchangeAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public EKeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return this.algorithm;
    }

    public void setSignatureAlgorithm(final ESignatureAlgorithm sigAlg) {
        this.sigAlg = sigAlg;
    }

    public ESignatureAlgorithm getSignatureAlgorithm() {
        return this.sigAlg;
    }

    public byte[] getDHGenerator() {
        return this.dhGen.clone();
    }

    public void setDHGenerator(final byte[] dhGen) {
        this.dhGen = dhGen.clone();
    }

    public byte[] getDHPrime() {
        return dhPrime.clone();
    }

    public void setDHPrime(final byte[] dhPrime) {
        this.dhPrime = dhPrime.clone();
    }

    public byte[] getDhPublic() {
        return dhPublic.clone();
    }

    public void setDhPublic(final byte[] dhPublic) {
        this.dhPublic = dhPublic.clone();
    }
}
