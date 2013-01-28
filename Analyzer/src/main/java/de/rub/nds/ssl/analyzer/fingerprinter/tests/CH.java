package de.rub.nds.ssl.analyzer.fingerprinter.tests;

import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;
import de.rub.nds.ssl.analyzer.parameters.ClientHelloParameters;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * Fingerprint the CH SSL message.
 *
 * @author Eugen Weiss -eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 18, 2012
 */
public final class CH extends AGenericFingerprintTest implements Observer {

    private static final byte FF = (byte) 0xff;
    private static final byte ZF = (byte) 0x0f;
    /**
     * Test headerParameters.
     */
    private ClientHelloParameters chParameters = new ClientHelloParameters();
    byte[] sessionID = new byte[]{FF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF, ZF,
        ZF, ZF, ZF, ZF, ZF, ZF
    };

    /**
     * Manipulate Client Hello message to perform fingerprinting tests.
     *
     * @param desc Test description
     * @param protocolVersion TLS protocol version
     * @param noSessionValue Session ID value if no sessionID is set
     * @param session Session ID value
     * @param sessionIdLength Length of the session id
     * @param cipherLength CipherSuite length
     * @param compMethod Compression method
     * @return Test results
     * @throws SocketException
     */
    public ResultWrapper fingerprintClientHello(final String desc,
            final byte[] protocolVersion, final byte[] noSessionValue,
            final byte[] session, final byte[] sessionIdLength,
            final byte[] cipherLength, final byte[] compMethod) throws
            SocketException {
        logger.info("++++Start Test No." + counter + "(" + desc + ")++++");
        workflow = new TLS10HandshakeWorkflow();
        //connect to test server
        workflow.connectToTestServer(getTargetHost(), getTargetPort());
        logger.info("Test Server: " + getTargetHost() + ":" + getTargetPort());

        //add the observer
        workflow.addObserver(this, EStates.CLIENT_HELLO);
        logger.info(EStates.CLIENT_HELLO.name() + " state is observed");

        //set the test headerParameters
        chParameters.setProtocolVersion(protocolVersion);
        chParameters.setNoSessionIdValue(noSessionValue);
        chParameters.setSessionId(session);
        chParameters.setSessionIdLen(sessionIdLength);
        chParameters.setCipherLen(cipherLength);
        chParameters.setCompMethod(compMethod);
        chParameters.setIdentifier(EFingerprintTests.CH);
        chParameters.setDescription(desc);

        try {
            workflow.start();

            this.counter++;
            logger.info("++++Test finished.++++");
        } finally {
            // close the Socket after the test run
            workflow.closeSocket();
        }

        return new ResultWrapper(chParameters, workflow.getTraceList(),
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
        MessageBuilder msgBuilder = new MessageBuilder();
        MessageContainer trace = null;
        EStates states = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states == EStates.CLIENT_HELLO) {
            ECipherSuite[] suites = new ECipherSuite[]{
                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
            CipherSuites cipherSuites = new CipherSuites();
            cipherSuites.setSuites(suites);
            RandomValue random = new RandomValue();
            byte[] compMethod = new byte[]{0x00};
            ClientHello clientHello = msgBuilder.
                    createClientHello(this.protocolVersion.
                    getId(),
                    random.encode(false), cipherSuites.encode(false), compMethod);
            byte[] payload;
            if (chParameters.getSessionId() != null) {
                byte[] session = chParameters.getSessionId();          
                clientHello.setSessionID(session);
            }
            if (chParameters.getCompMethod() != null) {
                clientHello.setCompressionMethod(chParameters.getCompMethod());
            }
            payload = clientHello.encode(true);
            if (chParameters.getProtocolVersion() != null) {
                byte[] protVersion = chParameters.getProtocolVersion();
                System.arraycopy(protVersion, 0, payload, 9, protVersion.length);
            }
            if (chParameters.getNoSessionIdValue() != null) {
                byte[] value = chParameters.getNoSessionIdValue();
                System.arraycopy(value, 0, payload, payload.length - 7,
                        value.length);
            }
            if (chParameters.getSessionIdLen() != null) {
                byte[] sLen = chParameters.getSessionIdLen();
                System.arraycopy(sLen, 0, payload, 43, sLen.length);
            }
            if (chParameters.getCipherLen() != null) {
                byte[] cLen = chParameters.getCipherLen();
                System.arraycopy(cLen, 0, payload, payload.length - 5,
                        cLen.length);
            }
            trace.setCurrentRecordBytes(payload);
            trace.setCurrentRecord(clientHello);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ResultWrapper[] call() throws Exception {
        Object[][] parameters = new Object[][]{
            {"Invalid protocol version 0xff,0xff",
                new byte[]{(byte) 0xff, (byte) 0xff}, null, null, null, null,
                null},
            {"Invalid protocol version 0x00,0x00",
                new byte[]{(byte) 0x00, (byte) 0x00}, null, null, null, null,
                null},
            {"Invalid protocol version SSLv3",
                new byte[]{(byte) 0x03, (byte) 0x00}, null, null, null, null,
                null},
            {"Invalid protocol version TLSv1.2",
                new byte[]{(byte) 0x03, (byte) 0x03}, null, null, null, null,
                null},
            {"No session ID defined but value is set to 0xff",
                null, new byte[]{(byte) 0xff}, null, null, null, null},
            {"256 Byte sessionID", null, null, sessionID, null, null, null},
            {"256 Byte sessionID and sessionID length 0x00", null, null,
                sessionID, new byte[]{(byte) 0x00}, null, null},
            {"Compression method 0xa1", null, null, null, null, null,
                new byte[]{(byte) 0xa1}},
            {"Wrong value for cipher suite length 0x01", null, null, null, null,
                new byte[]{(byte) 0x01}, null},
            {"Wrong value for cipher suite length 0x00", null, null, null, null,
                new byte[]{(byte) 0x00}, null}};

        // Print Test Banner
        printBanner();
        // execute test(s)
        ResultWrapper[] result = new ResultWrapper[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            result[i] = fingerprintClientHello((String) parameters[i][0],
                    (byte[]) parameters[i][1], (byte[]) parameters[i][2],
                    (byte[]) parameters[i][3], (byte[]) parameters[i][4],
                    (byte[]) parameters[i][5], (byte[]) parameters[i][6]);
            result[i].setTestName(this.getClass().getCanonicalName());
        }

        return result;
    }
}
