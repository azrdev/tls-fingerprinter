package de.rub.nds.ssl.attacks;

import de.rub.nds.ssl.attacker.bleichenbacher.Bleichenbacher;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.CiphertextOracle;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.PlaintextOracle;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackPlaintextTest {

    private static final String KEY_STORE_PATH = "1024.jks";
    private static final String KEY_NAME = "1024_rsa";
    private static final String PASSWORD = "password";
    
    /**
     * Plain PKCS 1024 bit
     */
    private static final byte[] plainPKCS1024 = new byte[]{
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
        (byte) 0x03, (byte) 0x01, // TLS 1.2 = 03 03
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

    public final void testBleichenbacherPlaintext()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = loadKeyStore(new FileInputStream(KEY_STORE_PATH),
                PASSWORD);

        byte[] plainBytes = plainPKCS1024;

        AOracle oracle = new PlaintextOracle(ks.getCertificate(KEY_NAME).
                getPublicKey(), OracleType.FFT, 128);

        Bleichenbacher attacker = new Bleichenbacher(plainBytes,
                oracle, true);
        attacker.attack();
    }
    
    public final void testBleichenbacherAttackCiphertext()
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = loadKeyStore(new FileInputStream(KEY_STORE_PATH),
                PASSWORD);
        PublicKey publicKey = ks.getCertificate(KEY_NAME).
                getPublicKey();
        PrivateKey privateKey =
                (PrivateKey) ks.getKey(KEY_NAME, PASSWORD.toCharArray());

        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] plainBytes = plainPKCS1024.clone();
        byte[] encBytes = cipher.doFinal(plainBytes);

        AOracle oracle = new CiphertextOracle(privateKey, publicKey,
                OracleType.FFT, 128);

        Bleichenbacher attacker = new Bleichenbacher(encBytes,
                oracle, true);
        attacker.attack();
    }

    private static KeyStore loadKeyStore(final InputStream keyStoreStream,
            final String keyStorePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(keyStoreStream, keyStorePassword.toCharArray());

        return ks;
    }
}
