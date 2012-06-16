/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author juraj
 */
public class StandardPlaintextOracle extends ATestOracle {
    
    public StandardPlaintextOracle(final PublicKey pubKey, 
            ATestOracle.OracleType oracleType) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.oracleType = oracleType;
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) {
        numberOfQueries++;
        return checkDecryptedBytes(msg);
    }

}
