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
        return cheat(msg, "2048_rsa", "password", "server.jks", "password");

        // analyze delay

        //      throw new UnsupportedOperationException("Not supported yet.");
    }
}
