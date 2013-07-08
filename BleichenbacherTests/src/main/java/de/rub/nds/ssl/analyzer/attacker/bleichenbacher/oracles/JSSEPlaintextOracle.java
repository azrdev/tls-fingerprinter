/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import java.io.InputStream;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 *
 * @author Sebastian Schinzel
 */
public class JSSEPlaintextOracle  extends AOracle {
    
    Cipher cipher;
    
    private static final int posOfTerminatingNullByte = 207;

    public JSSEPlaintextOracle() throws Exception {
        try {
            String keyName = "2048_rsa";
            ClassLoader classLoader = DetermineOracleType.class.getClassLoader();
            InputStream stream = classLoader.getResourceAsStream("2048.jks");

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(stream, "password".toCharArray());

            PublicKey pubKey = ks.getCertificate(keyName).getPublicKey();
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, "password".toCharArray());

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception ex) {
            Logger.getLogger(JSSEPlaintextOracle.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }
    
    

    @Override
    public boolean checkPKCSConformity(byte[] msg) {
        byte[] plainMsg;
        try {
            plainMsg = cipher.doFinal(msg);
        } catch (Exception ex) {
            Logger.getLogger(JSSEPlaintextOracle.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
        
        /*
         * The message must start with 00 02.
         * The padding must be ended with 00.
         * 
         */
        if(     plainMsg[0] != (byte) 0x0 &&
                plainMsg[1] != (byte) 0x2 &&
                plainMsg[posOfTerminatingNullByte] != (byte) 0x0) {
            return false;
        }
        /*
         * There must be no 0x0 byte in the first 8 bytes after
         * the starting 00 02 bytes.
         */
        for(int i = 2; i < 10; i++) {
            if(plainMsg[i] == (byte) 0x0) {
                return false;
            }
        }
        /*
         * There must be no 0x0 byte in the Padding.
         */
        for(int i = 10; i < posOfTerminatingNullByte; i++) {
            if(plainMsg[i] == (byte) 0x0) {
                return false;
            }
        }
        
        return true;
    }
    
}
