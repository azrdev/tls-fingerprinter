package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.analyzer.parameters.BleichenbacherParameters;
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
import de.rub.nds.ssl.stack.crypto.RsaUtil;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.MessageUtils;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Test for BleichenbacherPossible attack.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 12, 2012
 */
public final class BleichenbacherPossible extends AGenericFingerprintTest
        implements Observer {

    /**
     * BleichenbacherPossible test parameters.
     */
    private BleichenbacherParameters params = new BleichenbacherParameters();

    /**
     * Test if BleichenbacherPossible attack is possible.
     *
     * @param mode First two bytes of PKCS#1 message which defines the op-mode
     * @param separate Separate byte between padding and data in PKCS#1 message
     * @param version Protocol version
     * @param changePadding True if padding should be changed
     * @param position Position where padding is changed
     * @param anyPosition
     * @return Test result
     * @throws IOException
     */
    private TestResult fingerprintBleichenbacherPossible(final String desc,
            final byte[] mode, final byte[] separate,
            final byte[] version, final boolean changePadding,
            final MessageUtils.POSITIONS position, final Integer anyPosition)
            throws IOException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow(false);

        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");

        //set the test headerParameters
        params.setMode(mode);
        params.setSeparate(separate);
        params.setProtocolVersion(version);
        params.setChangePadding(changePadding);
        params.setPosition(position);
        params.setAnyPosition(anyPosition);
        params.setIdentifier(EFingerprintTests.BLEICHENBACHER_POSSIBLE);
        params.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new TestResult(params, workflow.getTraceList(),
                getAnalyzer());
    }

    /**
     * Test if BleichenbacherPossible attack is possible.
     *
     * @param desc Description
     * @param customMessage custom message, which will be encrypted
     * @return Test result
     * @throws IOException
     */
    private TestResult fingerprintBleichenbacherPossible(final String desc,
            final byte[] customMessage) throws IOException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow(false);

        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        workflow.addObserver(this, EStates.CLIENT_KEY_EXCHANGE);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");
        logger.info(EStates.CLIENT_KEY_EXCHANGE.name() + " state is observed");

        //set the test headerParameters
        params.setCustomMessage(customMessage);
        params.setIdentifier(EFingerprintTests.BLEICHENBACHER_POSSIBLE);
        params.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new TestResult(params, workflow.getTraceList(),
                getAnalyzer());
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
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
                    ClientHello clientHello = builder.
                            createClientHello(protocolVersion.
                            getId(),
                            random.encode(false),
                            suites.encode(false), new byte[]{0x00});
                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            protocolVersion,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms = new PreMasterSecret(protocolVersion);
                    workflow.setPreMasterSecret(pms);
                    pms.setProtocolVersion(protocolVersion);
                    byte[] encodedPMS = pms.encode(false);
                    if (params.getProtocolVersion() != null) {
                        byte[] version = params.getProtocolVersion();
                        System.arraycopy(version, 0, encodedPMS, 0,
                                version.length);
                    }
                    logger.debug("PreMasterSecret original: "
                            + Utility.bytesToHex(encodedPMS));
                    //encrypt the PreMasterSecret
                    EncPreMasterSecret encPMS =
                            new EncPreMasterSecret(pk);
                    BigInteger mod = null;
                    RSAPublicKey rsaPK = null;
                    if (pk != null && pk instanceof RSAPublicKey) {
                        rsaPK = (RSAPublicKey) pk;
                        mod = rsaPK.getModulus();
                    }

                    byte[] clear;
                    if (params.getCustomMessage() == null) {
                        int modLength = 0;
                        if (mod != null) {
                            modLength = mod.bitLength() / 8;
                        }
                        /*
                         * set the padding length of the PKCS#1 padding string (it
                         * is [<Modulus length> - <Data length> -3])
                         */
                        utils.setPaddingLength(
                                (modLength - encodedPMS.length - 3));
                        utils.setSeparateByte(params.getSeparate());
                        utils.setMode(params.getMode());
                        //generate the PKCS#1 padding string
                        byte[] padding = utils.createPaddingString(utils.
                                getPaddingLength());
                        if (params.isChangePadding()) {
                            if (params.getPosition() != null) {
                                padding = utils.changeByteArray(padding,
                                        params.getPosition(), (byte) 0x00);
                                utils.setPadding(padding);
                            } else if (params.getAnyPosition() > 0) {
                                padding = utils.changeArbitraryPos(padding,
                                        params.getAnyPosition(), (byte) 0x00);
                                utils.setPadding(padding);
                            }
                        }
                        //put the PKCS#1 pieces together
                        clear = utils.buildPKCS1Msg(encodedPMS);
                    } else {
                        clear = params.getCustomMessage();
                    }
                    logger.debug("Padded Premaster Secret: "
                            + Utility.bytesToHex(clear));
                    //compute c = m^e mod n (RSA encryption)
                    byte[] ciphertext = RsaUtil.pubOp(clear, rsaPK);
                    encPMS.setEncryptedPreMasterSecret(ciphertext);
                    cke.setExchangeKeys(encPMS);

                    trace.setOldRecord(trace.getCurrentRecord());
                    trace.setCurrentRecord(cke);
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TestResult[] call() throws Exception {
        Object[][] customParameters = new Object[][]{
            {"OK case",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                protocolVersion.getId(), false,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Wrong protocol version in PreMasterSecret",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                EProtocolVersion.SSL_3_0.getId(), false,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Invalid protocol version in PreMasterSecret",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                new byte[]{(byte) 0xff, (byte) 0xff}, false,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Separate byte not 0x00",
                new byte[]{0x00, 0x02}, new byte[]{0x01},
                protocolVersion.getId(), false,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Mode changed (first two bytes)",
                new byte[]{0x00, 0x01}, new byte[]{0x00},
                protocolVersion.getId(), false,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Zero byte at first position in padding",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                protocolVersion.getId(), true,
                MessageUtils.POSITIONS.FIRST, 0},
            {"Zero byte in the middle of the padding string",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                protocolVersion.getId(), true,
                MessageUtils.POSITIONS.MIDDLE, 0},
            {"Zero byte at the end of the padding string",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                protocolVersion.getId(), true,
                MessageUtils.POSITIONS.LAST, 0},
            {"Zero byte at custom position of the padding string",
                new byte[]{0x00, 0x02}, new byte[]{0x00},
                protocolVersion.getId(), true,
                null, 5}
        };

        // get key / message length
        RSAPublicKey pk = (RSAPublicKey) fetchServerPublicKey(
                getTargetHost(), getTargetPort());
        int messageLength = pk.getModulus().bitLength() / 8;
        Object[][] parameters = new Object[customParameters.length
                + messageLength - 1][];

        for (int i = 0; i < customParameters.length; i++) {
            parameters[i] = Arrays.copyOf(customParameters[i],
                    customParameters[i].length);
        }

        // create a custom message: 0x00 0x02 0x01 ... 0x01
        byte[] customMessage = new byte[messageLength];
        customMessage[0] = 0;
        customMessage[1] = 2;
        for (int i = 2; i < messageLength; i++) {
            customMessage[i] = 1;
        }
        // set the first custom message without padding bytes
        parameters[customParameters.length] = new Object[]{"No Zero Byte in "
            + "the message", customMessage};
        // iterate over all the bytes in the padded message starting behind 0002
        for (int i = 2; i < messageLength; i++) {
            int current = customParameters.length + i - 1;
            // clone the original message
            byte[] cm = Arrays.copyOf(customMessage, customMessage.length);
            // set the ith byte to 0
            cm[i] = 0;
            // set protocol version
            if ((messageLength - 2) > i) {
                cm[i + 1] = protocolVersion.getId()[0];
                cm[i + 2] = protocolVersion.getId()[1];
            }
            parameters[current] = new Object[]{"Zero byte at position " + i
                + " in the padding string", cm};
        }

        byte[] b = (byte[]) null;

        // Print Test Banner
        printBanner();
        // execute test(s)
        TestResult[] result = new TestResult[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].length > 2) {
                result[i] = fingerprintBleichenbacherPossible(
                        (String) parameters[i][0],
                        (byte[]) parameters[i][1], (byte[]) parameters[i][2],
                        (byte[]) parameters[i][3], (Boolean) parameters[i][4],
                        (MessageUtils.POSITIONS) parameters[i][5],
                        (Integer) parameters[i][6]);
                result[i].setTestName(this.getClass().getCanonicalName());
            } else {
                result[i] = fingerprintBleichenbacherPossible(
                        (String) parameters[i][0], (byte[]) parameters[i][1]);
                result[i].setTestName(this.getClass().getCanonicalName());
            }
        }

        return result;
    }

    public static PublicKey fetchServerPublicKey(final String serverHost,
            final int serverPort) throws
            GeneralSecurityException, IOException {
        // everyone is our friend - let's trust the whole world
        TrustManager trustManager = new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs,
                    String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs,
                    String authType) {
            }
        };

        // get a socket and extract the certificate
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, new TrustManager[]{trustManager}, null);
        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(
                serverHost, serverPort);
        sslSocket.setEnabledCipherSuites(buildRSACipherSuiteList(
                sslSocket.getEnabledCipherSuites()));
        sslSocket.startHandshake();
        SSLSession sslSession = sslSocket.getSession();
        Certificate[] peerCerts = sslSession.getPeerCertificates();

        return peerCerts[0].getPublicKey();
    }
    
    private static String[] buildRSACipherSuiteList(String[] suites) {
        List<String> cs = new ArrayList<String>(10);

        for (String suite : suites) {
            if (suite.contains("RSA")) {
                cs.add(suite);
            }
        }
        return cs.toArray(new String[cs.size()]);
    }
}