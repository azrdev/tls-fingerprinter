/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.rub.nds.ssl.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.misc.PKCS15Toolkit;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class PlaintextOracle extends AOracle {
    
    public PlaintextOracle(final PublicKey pubKey,
            final OracleType oracleType, final int blockSize) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.oracleType = oracleType;
        this.blockSize = blockSize;
        this.plaintextOracle = true;
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {
        this.numberOfQueries++;
        return PKCS15Toolkit.conformityChecker(msg, oracleType, blockSize);
    }

}
