/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TimingOracle extends ATimingOracle {
/**
     * Plain PKCS message
     */
    private static final byte[] plainPKCS = new byte[]{
        (byte) 0x00, (byte) 0x02, (byte) 0xf5, (byte) 0xa7, (byte) 0x9f,
        (byte) 0xcd, (byte) 0xb1, (byte) 0x27, (byte) 0xf9, (byte) 0x39,
        (byte) 0x15, (byte) 0x21, (byte) 0x49, (byte) 0x71, (byte) 0x65,
        (byte) 0x97, (byte) 0x33, (byte) 0x99, (byte) 0x6d, (byte) 0x9b,
        (byte) 0xcd, (byte) 0x6d, (byte) 0x4b, (byte) 0xe3, (byte) 0xf5,
        (byte) 0xfd, (byte) 0xb5, (byte) 0x71, (byte) 0xd5, (byte) 0x69,
        (byte) 0x71, (byte) 0x91, (byte) 0xb9, (byte) 0x39, (byte) 0xc9,
        (byte) 0x6d, (byte) 0xf5, (byte) 0x59, (byte) 0xf1, (byte) 0xb9,
        (byte) 0x97, (byte) 0xb7, (byte) 0x6b, (byte) 0xff, (byte) 0x33,
        (byte) 0xd1, (byte) 0x9b, (byte) 0x85, (byte) 0x13, (byte) 0xd5,
        (byte) 0x09, (byte) 0xb5, (byte) 0x33, (byte) 0xc9, (byte) 0x2d,
        (byte) 0xcf, (byte) 0xff, (byte) 0x53, (byte) 0xd7, (byte) 0xed,
        (byte) 0xd5, (byte) 0x1d, (byte) 0x45, (byte) 0x4d, (byte) 0xc9,
        (byte) 0xcb, (byte) 0x4b, (byte) 0x27, (byte) 0x21, (byte) 0x5f,
        (byte) 0x69, (byte) 0xf5, (byte) 0x67, (byte) 0x5d, (byte) 0xab,
        (byte) 0x9b, (byte) 0xf5, (byte) 0xc3, (byte) 0xc3, (byte) 0xaf,
        (byte) 0x7f, (byte) 0x6d, (byte) 0xa1, (byte) 0xe5, (byte) 0xfd,
        (byte) 0x3d, (byte) 0x93, (byte) 0xbb, (byte) 0x29, (byte) 0x11,
        (byte) 0x9b, (byte) 0x59, (byte) 0x5f, (byte) 0x11, (byte) 0x17,
        (byte) 0x17, (byte) 0xaf, (byte) 0x71, (byte) 0x33, (byte) 0xd7,
        (byte) 0x3f, (byte) 0x1b, (byte) 0x2f, (byte) 0x2b, (byte) 0xcd,
        (byte) 0x77, (byte) 0xfd, (byte) 0x3f, (byte) 0x5d, (byte) 0x67,
        (byte) 0x3b, (byte) 0x8f, (byte) 0xcd, (byte) 0xc5, (byte) 0x07,
        (byte) 0x6f, (byte) 0x59, (byte) 0x2b, (byte) 0xa7, (byte) 0x0d,
        (byte) 0xd3, (byte) 0x93, (byte) 0x87, (byte) 0x8d, (byte) 0x25,
        (byte) 0x47, (byte) 0x3b, (byte) 0xf7, (byte) 0x2d, (byte) 0xf9,
        (byte) 0x69, (byte) 0xdd, (byte) 0xe5, (byte) 0x85, (byte) 0x79,
        (byte) 0x7d, (byte) 0xc9, (byte) 0x09, (byte) 0xb7, (byte) 0xb7,
        (byte) 0x3d, (byte) 0x07, (byte) 0x23, (byte) 0x25, (byte) 0x07,
        (byte) 0x71, (byte) 0xb9, (byte) 0x1b, (byte) 0xcf, (byte) 0x15,
        (byte) 0x99, (byte) 0xdf, (byte) 0xb5, (byte) 0x6b, (byte) 0x29,
        (byte) 0x21, (byte) 0x4d, (byte) 0x4b, (byte) 0xf5, (byte) 0x31,
        (byte) 0x37, (byte) 0x9b, (byte) 0x43, (byte) 0x89, (byte) 0xd9,
        (byte) 0xef, (byte) 0x81, (byte) 0x55, (byte) 0x61, (byte) 0x4f,
        (byte) 0xc9, (byte) 0xff, (byte) 0xcf, (byte) 0x49, (byte) 0x73,
        (byte) 0xa9, (byte) 0x7f, (byte) 0xcb, (byte) 0xb5, (byte) 0x4f,
        (byte) 0x9d, (byte) 0xa5, (byte) 0xc9, (byte) 0x97, (byte) 0x3d,
        (byte) 0x9b, (byte) 0xf1, (byte) 0x9f, (byte) 0xf1, (byte) 0x95,
        (byte) 0xf9, (byte) 0x07, (byte) 0xa7, (byte) 0x95, (byte) 0xd5,
        (byte) 0xef, (byte) 0xd3, (byte) 0x4b, (byte) 0x27, (byte) 0x1f,
        (byte) 0x1f, (byte) 0x27, (byte) 0x9f, (byte) 0x5d, (byte) 0x8f,
        (byte) 0x39, (byte) 0x1b, (byte) 0x00, (byte) 0x03, (byte) 0x01,
        (byte) 0x06, (byte) 0x26, (byte) 0xa6, (byte) 0x40, (byte) 0x57,
        (byte) 0x4b, (byte) 0x50, (byte) 0xd6, (byte) 0xa3, (byte) 0xd0,
        (byte) 0x8a, (byte) 0x70, (byte) 0x16, (byte) 0x0a, (byte) 0x0d,
        (byte) 0xaf, (byte) 0x33, (byte) 0x2a, (byte) 0x7f, (byte) 0x9b,
        (byte) 0xc8, (byte) 0x65, (byte) 0xa7, (byte) 0xb5, (byte) 0x54,
        (byte) 0xe7, (byte) 0x48, (byte) 0x9f, (byte) 0x57, (byte) 0xda,
        (byte) 0xc9, (byte) 0xbf, (byte) 0x34, (byte) 0x8b, (byte) 0x8d,
        (byte) 0xd4, (byte) 0x84, (byte) 0xed, (byte) 0xc9, (byte) 0x63,
        (byte) 0x2b, (byte) 0x16, (byte) 0x6f, (byte) 0x2c, (byte) 0x38,
        (byte) 0x40};
    
    
    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public TimingOracle(final String serverAddress, final int serverPort)
            throws SocketException {
        super(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void trainOracle(byte[] firstRequest, byte[] secondRequest)
            throws OracleException {

        long delay;

        // train the oracle using the executeWorkflow functionality

        for (int i = 0; i < 10; i++) {
            exectuteWorkflow(firstRequest);
            delay = getTimeDelay(getWorkflow().getTraceList());
            System.out.println("delay 1: " + delay);

            exectuteWorkflow(secondRequest);
            delay = getTimeDelay(getWorkflow().getTraceList());
            System.out.println("delay 2: " + delay);
        }


        throw new UnsupportedOperationException("Not supported yet.");
    }

    private byte[] encrypt(final byte[] msg, final String keyName,
            final String keyPassword, final String keyStorePath,
            final String keyStorePassword) {
        byte[] result = null;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
                    toCharArray());

            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            result = cipher.doFinal(msg);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        }
        
        return result;
    }
    
    private boolean cheat(final byte[] msg, final String keyName,
            final String keyPassword, final String keyStorePath,
            final String keyStorePassword) {
        boolean result = false;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            PublicKey publicKey = ks.getCertificate(keyName).getPublicKey();
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyName, keyPassword.
                    toCharArray());

            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plainMessage = cipher.doFinal(msg);

            StdPlainOracle plainOracle = new StdPlainOracle(publicKey,
                    OracleType.JSSE, blockSize);
            result = plainOracle.checkDecryptedBytes(msg);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(TimingOracle.class.getName()).
                    log(Level.SEVERE, null, ex);
        }

        return result;
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {

//        exectuteWorkflow(msg);

//        long delay = getTimeDelay(getWorkflow().getTraceList());
        byte[] encPMS = encrypt(plainPKCS, "2048_rsa", "password", "server.jks", "password");
        return cheat(encPMS, "2048_rsa", "password", "server.jks", "password");

        // analyze delay

        //      throw new UnsupportedOperationException("Not supported yet.");
    }
}
