/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.misc.PKCS15Toolkit;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Christopher Meyer christopher.meyer@rub.de
 * @version 0.1
 */
public class CiphertextOracle extends AOracle {

    private PrivateKey privateKey;
    private Cipher cipher;

    public CiphertextOracle(final PrivateKey privKey, final PublicKey pubKey,
            final OracleType oracleType, final int blockSize)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException {
        this.publicKey = (RSAPublicKey) pubKey;
        this.oracleType = oracleType;
        this.blockSize = blockSize;
        this.privateKey = privKey;

        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {
        this.numberOfQueries++;

        try {
            byte[] plainMsg = cipher.doFinal(msg);
            return PKCS15Toolkit.conformityChecker(plainMsg, oracleType,
                    blockSize);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new OracleException("Terrible things happened...", e);
        }
    }
}
